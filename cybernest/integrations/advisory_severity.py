"""Resolve validated CVSS data from GitHub Advisory and NVD APIs."""

import json
import math
import re
from dataclasses import dataclass, replace
from datetime import timezone
from email.utils import parsedate_to_datetime
from http.client import HTTPException
from time import monotonic, time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from cybernest.integrations.severity_cache import PersistentSeverityCache


@dataclass(frozen=True)
class SeverityInfo:
    severity: str = "UNKNOWN"
    cvss_score: float | None = None
    cvss_vector: str = ""
    cvss_version: str = ""
    source: str = ""
    source_url: str = ""
    lookup_status: str = "not_available"
    reported_severity: str = ""
    selection_reason: str = ""
    data_origin: str = "unknown"
    cache_age_seconds: float | None = None


class AdvisoryLookupError(Exception):
    def __init__(
        self,
        status: str,
        *,
        provider: str = "",
        retry_after_seconds: float | None = None,
    ):
        self.status = status
        self.provider = provider
        self.retry_after_seconds = retry_after_seconds
        super().__init__(status)


class AdvisorySeverityResolver:
    _TIMEOUT_SECONDS = 3
    _SUCCESS_CACHE_TTL_SECONDS = 3600
    _NOT_AVAILABLE_CACHE_TTL_SECONDS = 300
    _DEFAULT_RATE_LIMIT_COOLDOWN_SECONDS = 60
    _MAX_RATE_LIMIT_COOLDOWN_SECONDS = 600

    def __init__(self, cache_path=None):
        self._cache: dict[str, tuple[float, float, SeverityInfo]] = {}
        self._persistent_cache = PersistentSeverityCache(
            cache_path, self._SUCCESS_CACHE_TTL_SECONDS
        )
        self._provider_cooldowns: dict[str, float] = {}

    def resolve(self, identifiers: list[str]) -> SeverityInfo:
        normalized = self._normalize_identifiers(identifiers)
        resolved = []
        statuses = []
        diagnostics = []
        # Query both sources; apply the same explicit source policy regardless of alias order.
        ordered = sorted(normalized, key=lambda item: 0 if item.startswith("CVE-") else 1)
        for identifier in ordered:
            provider = self._provider_for_identifier(identifier)
            cached = self._cache.get(identifier)
            if cached and monotonic() < cached[0]:
                age = max(0.0, time() - cached[1])
                result = replace(cached[2], data_origin="cache", cache_age_seconds=age)
            else:
                self._cache.pop(identifier, None)
                persistent_entry, cache_age = self._persistent_cache.get(identifier)
                result = self._restore_cache_entry(
                    identifier, persistent_entry, cache_age
                ) if persistent_entry is not None else None
                if result is not None:
                    fetched_at = time() - (cache_age or 0.0)
                    remaining = max(0.0, self._SUCCESS_CACHE_TTL_SECONDS - (cache_age or 0.0))
                    self._cache[identifier] = (
                        monotonic() + remaining,
                        fetched_at,
                        result,
                    )
                elif provider and monotonic() < self._provider_cooldowns.get(provider, 0):
                    result = SeverityInfo(lookup_status="rate_limited")
                else:
                    try:
                        result = self._resolve_identifier(identifier)
                    except AdvisoryLookupError as error:
                        result = SeverityInfo(lookup_status=error.status)
                        if error.status == "rate_limited" and provider:
                            delay = (
                                error.retry_after_seconds
                                if error.retry_after_seconds is not None
                                else self._DEFAULT_RATE_LIMIT_COOLDOWN_SECONDS
                            )
                            delay = min(max(delay, 1), self._MAX_RATE_LIMIT_COOLDOWN_SECONDS)
                            self._provider_cooldowns[provider] = monotonic() + delay
                    if result.lookup_status == "resolved":
                        fetched_at = time()
                        if self._is_cacheable(identifier, result):
                            try:
                                self._persistent_cache.put(
                                    identifier, self._cache_record(result), now=fetched_at
                                )
                            except (OSError, TimeoutError, ValueError):
                                # A cache write must never turn a valid live lookup into a scan failure.
                                pass
                        result = replace(result, data_origin="live", cache_age_seconds=None)
                        self._cache[identifier] = (
                            monotonic() + self._SUCCESS_CACHE_TTL_SECONDS,
                            fetched_at,
                            result,
                        )
                    elif result.lookup_status == "not_available":
                        self._cache[identifier] = (
                            monotonic() + self._NOT_AVAILABLE_CACHE_TTL_SECONDS,
                            time(),
                            result,
                        )

            if result.lookup_status == "resolved":
                resolved.append(result)
            else:
                statuses.append(result.lookup_status)
                if result.lookup_status != "not_available":
                    diagnostics.append(f"{provider or identifier}: {result.lookup_status}")

        if resolved:
            selected = max(resolved, key=self._result_priority)
            reason = (
                f"Selected {selected.source} CVSS {selected.cvss_version} "
                "using the deterministic source and version priority policy."
            )
            if diagnostics:
                reason += " Other advisory lookups: " + ", ".join(dict.fromkeys(diagnostics)) + "."
            elif statuses:
                reason += " Other advisory lookups had no usable CVSS data."
            return replace(selected, selection_reason=reason)
        status = self._best_status(statuses)
        reason = (
            "No usable CVSS record was returned; severity remains UNKNOWN."
            if status == "not_available"
            else f"CVSS lookup did not complete with usable data ({status}); severity remains UNKNOWN."
        )
        if diagnostics:
            reason += " Provider status: " + ", ".join(dict.fromkeys(diagnostics)) + "."
        return SeverityInfo(lookup_status=status, selection_reason=reason)

    @classmethod
    def _is_cacheable(cls, identifier: str, result: SeverityInfo) -> bool:
        identifier = identifier.upper()
        if not (identifier.startswith("CVE-") or identifier.startswith("GHSA-")):
            return False
        score = cls._valid_score(result.cvss_score)
        version = result.cvss_version
        if (
            result.lookup_status != "resolved"
            or score is None
            or version not in {"2.0", "3.0", "3.1", "4.0"}
            or not cls._valid_vector(result.cvss_vector, version)
            or result.severity != cls._severity_from_cvss_score(score, version)
        ):
            return False
        if identifier.startswith("CVE-"):
            return result.source.lower().startswith("nvd")
        return result.source == "GitHub Advisory Database"

    @classmethod
    def _cache_record(cls, result: SeverityInfo) -> dict[str, object]:
        return {
            "severity": result.severity,
            "cvss_score": result.cvss_score,
            "cvss_vector": result.cvss_vector,
            "cvss_version": result.cvss_version,
            "source": result.source,
            "reported_severity": result.reported_severity,
        }

    @classmethod
    def _restore_cache_entry(
        cls,
        identifier: str,
        entry: dict | None,
        age: float | None,
    ) -> SeverityInfo | None:
        if not isinstance(entry, dict) or age is None:
            return None
        score = cls._valid_score(entry.get("cvss_score"))
        vector = entry.get("cvss_vector")
        version = entry.get("cvss_version")
        source = entry.get("source")
        if not all(isinstance(value, str) for value in (vector, version, source)):
            return None
        if identifier.startswith("CVE-"):
            if not source.lower().startswith("nvd"):
                return None
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={quote(identifier)}"
        elif identifier.startswith("GHSA-"):
            if source != "GitHub Advisory Database":
                return None
            url = f"https://api.github.com/advisories/{quote(identifier)}"
        else:
            return None
        if (
            score is None
            or version not in {"2.0", "3.0", "3.1", "4.0"}
            or cls._cvss_version(vector) != version
            or not cls._valid_vector(vector, version)
        ):
            return None
        severity = cls._severity_from_cvss_score(score, version)
        if entry.get("severity") != severity:
            return None
        reported = cls._normalize_severity(entry.get("reported_severity"))
        return SeverityInfo(
            severity=severity,
            cvss_score=score,
            cvss_vector=vector,
            cvss_version=version,
            source=source,
            source_url=url,
            lookup_status="resolved",
            reported_severity=reported,
            selection_reason=f"Loaded validated {source} CVSS data from persistent cache ({age:.1f}s old).",
            data_origin="cache",
            cache_age_seconds=age,
        )

    @staticmethod
    def _provider_for_identifier(identifier: str) -> str:
        if identifier.startswith("CVE-"):
            return "NVD"
        if identifier.startswith("GHSA-"):
            return "GitHub"
        return ""

    @staticmethod
    def _provider_from_url(url: str) -> str:
        lowered = url.lower()
        if "nvd.nist.gov" in lowered:
            return "NVD"
        if "api.github.com" in lowered:
            return "GitHub"
        return ""

    @staticmethod
    def _retry_delay(headers) -> float | None:
        retry_after = headers.get("Retry-After") if headers else None
        if retry_after:
            try:
                return max(0.0, float(retry_after))
            except (TypeError, ValueError):
                try:
                    retry_at = parsedate_to_datetime(retry_after)
                    if retry_at.tzinfo is None:
                        retry_at = retry_at.replace(tzinfo=timezone.utc)
                    return max(0.0, retry_at.timestamp() - time())
                except (TypeError, ValueError, OverflowError):
                    pass
        reset = headers.get("X-RateLimit-Reset") if headers else None
        try:
            return max(0.0, float(reset) - time()) if reset else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _normalize_identifiers(identifiers: list[str]) -> list[str]:
        return list(dict.fromkeys(
            value.strip().upper()
            for value in identifiers
            if isinstance(value, str) and value.strip()
        ))

    @staticmethod
    def _best_status(statuses: list[str]) -> str:
        for status in ("rate_limited", "network_error", "api_error"):
            if status in statuses:
                return status
        return "not_available"

    @staticmethod
    def _source_priority(source: str) -> int:
        source = source.lower()
        if source == "nvd":
            return 4
        if source.startswith("github advisory database"):
            return 3
        if source.startswith("nvd (primary:"):
            return 2
        if source.startswith("nvd (secondary:"):
            return 1
        return 0

    @classmethod
    def _result_priority(cls, result: SeverityInfo) -> tuple[int, int]:
        return (
            cls._source_priority(result.source),
            {"4.0": 4, "3.1": 3, "3.0": 2, "2.0": 1}.get(
                result.cvss_version, 0
            ),
        )

    def _resolve_identifier(self, identifier: str) -> SeverityInfo:
        if identifier.startswith("GHSA-"):
            return self._from_github(identifier)
        if identifier.startswith("CVE-"):
            return self._from_nvd(identifier)
        return SeverityInfo()

    def _get_json(self, url: str, *, accept: str) -> dict | None:
        request = Request(url, headers={
            "Accept": accept,
            "User-Agent": "CyberNest-security-scanner",
        })
        try:
            with urlopen(request, timeout=self._TIMEOUT_SECONDS) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            body = ""
            try:
                body = error.read().decode("utf-8", errors="replace").lower()
            except (OSError, AttributeError):
                pass
            headers = error.headers or {}
            rate_limited = (
                error.code == 429
                or headers.get("Retry-After") is not None
                or headers.get("X-RateLimit-Remaining") == "0"
                or "rate limit exceeded" in body
                or "secondary rate limit" in body
            )
            error.close()
            if error.code == 404:
                return None
            provider = self._provider_from_url(url)
            if rate_limited:
                raise AdvisoryLookupError(
                    "rate_limited",
                    provider=provider,
                    retry_after_seconds=self._retry_delay(headers),
                ) from error
            raise AdvisoryLookupError("api_error", provider=provider) from error
        except (URLError, HTTPException, TimeoutError, OSError) as error:
            raise AdvisoryLookupError(
                "network_error", provider=self._provider_from_url(url)
            ) from error
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AdvisoryLookupError(
                "api_error", provider=self._provider_from_url(url)
            ) from error
        if not isinstance(payload, dict):
            raise AdvisoryLookupError("api_error", provider=self._provider_from_url(url))
        return payload

    def _from_github(self, identifier: str) -> SeverityInfo:
        url = f"https://api.github.com/advisories/{quote(identifier)}"
        data = self._get_json(url, accept="application/vnd.github+json")
        if not data:
            return SeverityInfo()

        candidates = []
        cvss_severities = data.get("cvss_severities")
        if isinstance(cvss_severities, dict):
            candidates.extend((version, cvss_severities.get(key)) for version, key in (
                ("4.0", "cvss_v4"), ("3.1", "cvss_v3")
            ))
        candidates.append(("", data.get("cvss")))
        reported_severity = self._normalize_severity(data.get("severity"))

        for declared_version, cvss in candidates:
            if not isinstance(cvss, dict):
                continue
            score = self._valid_score(cvss.get("score"))
            vector = cvss.get("vector_string")
            vector = vector.strip() if isinstance(vector, str) else ""
            version = self._cvss_version(vector) or declared_version
            if score is None or not self._valid_vector(vector, version):
                continue
            return SeverityInfo(
                severity=self._severity_from_cvss_score(score, version),
                cvss_score=score,
                cvss_vector=vector,
                cvss_version=version,
                source="GitHub Advisory Database",
                source_url=url,
                lookup_status="resolved",
                reported_severity=reported_severity,
            )
        return SeverityInfo()

    def _from_nvd(self, identifier: str) -> SeverityInfo:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={quote(identifier)}"
        data = self._get_json(url, accept="application/json")
        if not data:
            return SeverityInfo()
        vulnerabilities = data.get("vulnerabilities")
        if not isinstance(vulnerabilities, list) or not vulnerabilities:
            return SeverityInfo()
        first = vulnerabilities[0]
        cve = first.get("cve") if isinstance(first, dict) else None
        if not isinstance(cve, dict):
            return SeverityInfo()
        if str(cve.get("id", "")).upper() != identifier:
            raise AdvisoryLookupError("api_error")
        metrics = cve.get("metrics")
        if not isinstance(metrics, dict):
            return SeverityInfo()

        candidates = []
        for version, name in (("4.0", "cvssMetricV40"), ("3.1", "cvssMetricV31"),
                              ("3.0", "cvssMetricV30"), ("2.0", "cvssMetricV2")):
            entries = metrics.get(name, [])
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                cvss = entry.get("cvssData")
                if not isinstance(cvss, dict):
                    continue
                score = self._valid_score(cvss.get("baseScore"))
                vector = cvss.get("vectorString")
                vector = vector.strip() if isinstance(vector, str) else ""
                actual_version = self._cvss_version(vector) or version
                if score is None or not self._valid_vector(vector, actual_version):
                    continue
                source_id = entry.get("source")
                source_id = source_id.strip() if isinstance(source_id, str) else ""
                metric_type = str(entry.get("type", "")).lower()
                if source_id.lower() == "nvd@nist.gov" and metric_type == "primary":
                    source = "NVD"
                elif metric_type == "primary":
                    source = f"NVD (primary: {source_id or 'unknown source'})"
                else:
                    source = f"NVD (secondary: {source_id or 'unknown source'})"
                severity = self._normalize_severity(
                    cvss.get("baseSeverity") or entry.get("baseSeverity")
                )
                derived = self._severity_from_cvss_score(score, actual_version)
                candidates.append(SeverityInfo(
                    severity=derived,
                    cvss_score=score,
                    cvss_vector=vector,
                    cvss_version=actual_version,
                    source=source,
                    source_url=url,
                    lookup_status="resolved",
                    reported_severity=severity,
                ))
        if not candidates:
            return SeverityInfo()
        return max(candidates, key=self._result_priority)

    @staticmethod
    def _valid_score(value) -> float | None:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        score = float(value)
        return score if math.isfinite(score) and 0 <= score <= 10 else None

    @staticmethod
    def _cvss_version(vector: str) -> str:
        match = re.match(r"^CVSS:(\d+\.\d+)/", vector)
        return match.group(1) if match else "2.0" if vector.startswith("AV:") else ""

    @classmethod
    def _valid_vector(cls, vector: str, version: str) -> bool:
        if not vector or not version:
            return False
        if version == "2.0":
            required = {"AV", "AC", "Au", "C", "I", "A"}
            pattern = r"^(AV:[NALP]/AC:[LMH]/Au:[NS]/C:[NPC]/I:[NPC]/A:[NPC])$"
            return bool(re.fullmatch(pattern, vector))
        prefix = f"CVSS:{version}/"
        if not vector.startswith(prefix):
            return False
        pairs = vector[len(prefix):].split("/")
        if any(":" not in pair for pair in pairs):
            return False
        metrics = dict(pair.split(":", 1) for pair in pairs)
        if len(metrics) != len(pairs):
            return False
        if version in {"3.0", "3.1"}:
            allowed = {
                "AV": {"N", "A", "L", "P"}, "AC": {"L", "H"},
                "PR": {"N", "L", "H"}, "UI": {"N", "R"},
                "S": {"U", "C"}, "C": {"H", "L", "N"},
                "I": {"H", "L", "N"}, "A": {"H", "L", "N"},
            }
            return all(key in metrics and metrics[key] in values for key, values in allowed.items())
        if version == "4.0":
            allowed = {
                "AV": {"N", "A", "L", "P"}, "AC": {"L", "H"},
                "AT": {"N", "P"}, "PR": {"N", "L", "H"},
                "UI": {"N", "P", "A"},
                "VC": {"H", "L", "N"}, "VI": {"H", "L", "N"},
                "VA": {"H", "L", "N"}, "SC": {"H", "L", "N"},
                "SI": {"H", "L", "N"}, "SA": {"H", "L", "N"},
            }
            return all(key in metrics and metrics[key] in values for key, values in allowed.items())
        return False

    @staticmethod
    def _normalize_severity(value) -> str:
        if not isinstance(value, str):
            return "UNKNOWN"
        normalized = value.strip().upper()
        if normalized == "MODERATE":
            normalized = "MEDIUM"
        return normalized if normalized in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"} else "UNKNOWN"

    @staticmethod
    def _severity_from_cvss_score(score: float, version: str) -> str:
        if score == 0:
            return "LOW" if version == "2.0" else "NONE"
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"
