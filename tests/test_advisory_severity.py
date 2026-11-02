import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from io import BytesIO
from unittest.mock import MagicMock

from cybernest.integrations.advisory_severity import (
    AdvisoryLookupError,
    AdvisorySeverityResolver,
    SeverityInfo,
)


class TestAdvisorySeverityResolver(unittest.TestCase):
    def setUp(self):
        self.temp_cache = tempfile.TemporaryDirectory(prefix="cybernest-cvss-test-")
        self.cache_path = Path(self.temp_cache.name) / "cvss-cache-v1.json"
        self.cache_path_patcher = patch(
            "cybernest.integrations.advisory_severity.PersistentSeverityCache.default_path",
            return_value=self.cache_path,
        )
        self.cache_path_patcher.start()

    def tearDown(self):
        self.cache_path_patcher.stop()
        self.temp_cache.cleanup()


    @patch("cybernest.integrations.advisory_severity.AdvisorySeverityResolver._get_json")
    def test_github_skips_invalid_cvss_v4_and_uses_valid_v3(self, mock_get_json):
        mock_get_json.return_value = {
            "severity": "high",
            "cvss_severities": {
                "cvss_v4": {
                    "score": float("nan"),
                    "vector_string": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
                },
                "cvss_v3": {
                    "score": 8.1,
                    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                },
            },
        }

        result = AdvisorySeverityResolver().resolve(["GHSA-1234-abcd-5678"])

        self.assertEqual(result.severity, "HIGH")
        self.assertEqual(result.cvss_score, 8.1)
        self.assertEqual(result.cvss_version, "3.1")
        self.assertEqual(result.lookup_status, "resolved")
        self.assertEqual(result.severity, "HIGH")

    @patch("cybernest.integrations.advisory_severity.AdvisorySeverityResolver._get_json")
    def test_github_falls_back_when_v4_score_is_missing(self, mock_get_json):
        mock_get_json.return_value = {
            "severity": "medium",
            "cvss_severities": {
                "cvss_v4": {
                    "score": 0.0,
                    "vector_string": "",
                },
                "cvss_v3": {
                    "score": 5.4,
                    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                },
            },
        }

        result = AdvisorySeverityResolver().resolve(["GHSA-1234-abcd-5678"])

        self.assertEqual(result.cvss_score, 5.4)
        self.assertEqual(result.cvss_version, "3.1")
        self.assertEqual(result.lookup_status, "resolved")

    def test_rejects_invalid_cvss_scores(self):
        for score in (float("nan"), float("inf"), -0.1, 10.1, "8.1", True):
            with self.subTest(score=score):
                self.assertIsNone(AdvisorySeverityResolver._valid_score(score))

    @patch("cybernest.integrations.advisory_severity.AdvisorySeverityResolver._get_json")
    def test_nvd_uses_matching_cve_and_prefers_its_primary_metric(self, mock_get_json):
        mock_get_json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2026-1234",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "cna@example.org",
                                "type": "Secondary",
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                },
                            },
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "baseScore": 6.5,
                                    "baseSeverity": "MEDIUM",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                                },
                            },
                        ],
                    },
                },
            }],
        }

        result = AdvisorySeverityResolver().resolve(["CVE-2026-1234"])

        self.assertEqual(result.cvss_score, 6.5)
        self.assertEqual(result.severity, "MEDIUM")
        self.assertEqual(result.source, "NVD")
        self.assertEqual(result.cvss_version, "3.1")
        self.assertEqual(result.lookup_status, "resolved")

    @patch("cybernest.integrations.advisory_severity.AdvisorySeverityResolver._get_json")
    def test_nvd_skips_invalid_v4_and_uses_v3(self, mock_get_json):
        mock_get_json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2026-1234",
                    "metrics": {
                        "cvssMetricV40": [{
                            "source": "cna@example.org",
                            "type": "Primary",
                            "cvssData": {
                                "baseScore": float("nan"),
                                "vectorString": "CVSS:4.0/invalid",
                            },
                        }],
                        "cvssMetricV31": [{
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                            },
                        }],
                    },
                },
            }],
        }

        result = AdvisorySeverityResolver().resolve(["CVE-2026-1234"])

        self.assertEqual(result.cvss_score, 7.5)
        self.assertEqual(result.cvss_version, "3.1")
        self.assertEqual(result.severity, "HIGH")

    @patch("cybernest.integrations.advisory_severity.AdvisorySeverityResolver._get_json")
    def test_nvd_rejects_a_response_for_a_different_cve(self, mock_get_json):
        mock_get_json.return_value = {
            "vulnerabilities": [{"cve": {"id": "CVE-2026-9999"}}],
        }

        result = AdvisorySeverityResolver().resolve(["CVE-2026-1234"])

        self.assertEqual(result.severity, "UNKNOWN")
        self.assertIsNone(result.cvss_score)
        self.assertEqual(result.lookup_status, "api_error")

    @patch("cybernest.integrations.advisory_severity.urlopen")
    def test_http_429_is_reported_as_rate_limited(self, mock_urlopen):
        mock_urlopen.side_effect = HTTPError(
            "https://api.github.com/advisories/GHSA-1234-abcd-5678",
            429,
            "rate limited",
            {},
            None,
        )

        result = AdvisorySeverityResolver().resolve(["GHSA-1234-abcd-5678"])

        self.assertEqual(result.severity, "UNKNOWN")
        self.assertIsNone(result.cvss_score)
        self.assertEqual(result.lookup_status, "rate_limited")

    @patch("cybernest.integrations.advisory_severity.urlopen")
    def test_network_failure_is_reported_without_raising(self, mock_urlopen):
        mock_urlopen.side_effect = URLError("offline")

        result = AdvisorySeverityResolver().resolve(["CVE-2026-1234"])

        self.assertEqual(result.severity, "UNKNOWN")
        self.assertIsNone(result.cvss_score)
        self.assertEqual(result.lookup_status, "network_error")

    @patch("cybernest.integrations.advisory_severity.AdvisorySeverityResolver._get_json")
    def test_missing_cvss_is_not_available(self, mock_get_json):
        mock_get_json.return_value = {
            "severity": "high",
            "cvss_severities": {
                "cvss_v4": {"score": -1},
                "cvss_v3": {"score": 11},
            },
        }

        result = AdvisorySeverityResolver().resolve(["GHSA-1234-abcd-5678"])

        self.assertEqual(result.severity, "UNKNOWN")
        self.assertIsNone(result.cvss_score)
        self.assertEqual(result.lookup_status, "not_available")

    @patch("cybernest.integrations.advisory_severity.AdvisorySeverityResolver._get_json")
    def test_valid_cvss_zero_keeps_unknown_severity_but_is_resolved(self, mock_get_json):
        mock_get_json.return_value = {
            "severity": "unknown",
            "cvss_severities": {
                "cvss_v4": {
                    "score": 0.0,
                    "vector_string": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
                },
            },
            "severity": "high",
        }

        result = AdvisorySeverityResolver().resolve(["GHSA-1234-abcd-5678"])

        self.assertEqual(result.severity, "NONE")
        self.assertEqual(result.cvss_score, 0.0)
        self.assertEqual(result.lookup_status, "resolved")
        self.assertEqual(result.reported_severity, "HIGH")

    @patch("cybernest.integrations.advisory_severity.AdvisorySeverityResolver._get_json")
    def test_valid_result_is_cached(self, mock_get_json):
        mock_get_json.return_value = {
            "severity": "high",
            "cvss_severities": {
                "cvss_v3": {
                    "score": 8.1,
                    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                },
            },
        }
        resolver = AdvisorySeverityResolver()

        resolver.resolve(["GHSA-1234-abcd-5678"])
        resolver.resolve(["GHSA-1234-abcd-5678"])

        mock_get_json.assert_called_once()

    @patch("cybernest.integrations.advisory_severity.AdvisorySeverityResolver._get_json")
    def test_not_available_result_is_cached(self, mock_get_json):
        mock_get_json.return_value = {}
        resolver = AdvisorySeverityResolver()

        resolver.resolve(["GHSA-1234-abcd-5678"])
        resolver.resolve(["GHSA-1234-abcd-5678"])

        mock_get_json.assert_called_once()

    @patch("cybernest.integrations.advisory_severity.AdvisorySeverityResolver._get_json")
    def test_transient_error_is_not_cached_and_next_call_retries(self, mock_get_json):
        mock_get_json.side_effect = [
            AdvisoryLookupError("network_error"),
            {"severity": "high", "cvss": {
                "score": 8.1,
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            }},
        ]
        resolver = AdvisorySeverityResolver()

        first = resolver.resolve(["GHSA-1234-abcd-5678"])
        second = resolver.resolve(["GHSA-1234-abcd-5678"])

        self.assertEqual(first.lookup_status, "network_error")
        self.assertEqual(second.lookup_status, "resolved")
        self.assertEqual(mock_get_json.call_count, 2)

    def test_persistent_cache_hit_preserves_validated_provenance(self):
        live = SeverityInfo(
            severity="HIGH", cvss_score=8.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            cvss_version="3.1", source="NVD", lookup_status="resolved",
            reported_severity="HIGH",
        )
        with patch.object(AdvisorySeverityResolver, "_resolve_identifier", return_value=live) as resolve_live:
            first = AdvisorySeverityResolver(cache_path=self.cache_path).resolve(["CVE-2026-1234"])
        self.assertEqual(first.data_origin, "live")

        with patch.object(
            AdvisorySeverityResolver,
            "_resolve_identifier",
            side_effect=AdvisoryLookupError("rate_limited"),
        ) as resolve_network:
            second = AdvisorySeverityResolver(cache_path=self.cache_path).resolve(["CVE-2026-1234"])

        self.assertEqual(second.lookup_status, "resolved")
        self.assertEqual(second.data_origin, "cache")
        self.assertGreaterEqual(second.cache_age_seconds, 0)
        self.assertEqual(second.source, "NVD")
        self.assertEqual(second.cvss_score, 8.1)
        resolve_live.assert_called_once()
        resolve_network.assert_not_called()
        payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema_version"], 1)
        self.assertIn("CVE-2026-1234", payload["entries"])
        self.assertNotIn("source_url", payload["entries"]["CVE-2026-1234"])

    def test_persistent_cache_is_available_in_a_new_process(self):
        live = SeverityInfo(
            severity="HIGH", cvss_score=8.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            cvss_version="3.1", source="NVD", lookup_status="resolved",
        )
        with patch.object(AdvisorySeverityResolver, "_resolve_identifier", return_value=live):
            AdvisorySeverityResolver(cache_path=self.cache_path).resolve(["CVE-2026-1234"])

        script = (
            "import json,sys; from unittest.mock import patch; "
            "from cybernest.integrations.advisory_severity import AdvisorySeverityResolver,AdvisoryLookupError; "
            "resolver=AdvisorySeverityResolver(cache_path=sys.argv[1]); "
            "patcher=patch.object(AdvisorySeverityResolver,'_resolve_identifier',side_effect=AdvisoryLookupError('rate_limited')); "
            "patcher.start(); result=resolver.resolve(['CVE-2026-1234']); "
            "print(json.dumps({'status':result.lookup_status,'origin':result.data_origin,'score':result.cvss_score}))"
        )
        result = subprocess.run(
            [sys.executable, "-c", script, str(self.cache_path)],
            capture_output=True, text=True, check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {
            "status": "resolved", "origin": "cache", "score": 8.1,
        })

    def test_persistent_cache_expiry_forces_live_lookup(self):
        live = SeverityInfo(
            severity="HIGH", cvss_score=8.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            cvss_version="3.1", source="NVD", lookup_status="resolved",
        )
        with patch.object(AdvisorySeverityResolver, "_resolve_identifier", return_value=live):
            AdvisorySeverityResolver(cache_path=self.cache_path).resolve(["CVE-2026-1234"])
        payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
        payload["entries"]["CVE-2026-1234"]["fetched_at"] -= 3601
        payload["entries"]["CVE-2026-1234"]["expires_at"] -= 3601
        self.cache_path.write_text(json.dumps(payload), encoding="utf-8")

        with patch.object(
            AdvisorySeverityResolver,
            "_resolve_identifier",
            side_effect=AdvisoryLookupError("rate_limited"),
        ) as lookup:
            result = AdvisorySeverityResolver(cache_path=self.cache_path).resolve(["CVE-2026-1234"])

        self.assertEqual(result.lookup_status, "rate_limited")
        self.assertNotEqual(result.data_origin, "cache")
        lookup.assert_called_once()

    def test_corrupt_persistent_cache_is_ignored_and_live_data_still_works(self):
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text("{not-json", encoding="utf-8")
        live = SeverityInfo(
            severity="HIGH", cvss_score=8.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            cvss_version="3.1", source="NVD", lookup_status="resolved",
        )

        with patch.object(AdvisorySeverityResolver, "_resolve_identifier", return_value=live):
            result = AdvisorySeverityResolver(cache_path=self.cache_path).resolve(["CVE-2026-1234"])

        self.assertEqual(result.lookup_status, "resolved")
        self.assertEqual(result.data_origin, "live")
        self.assertEqual(json.loads(self.cache_path.read_text(encoding="utf-8"))["schema_version"], 1)

    def test_persistent_alias_records_remain_separate_and_source_priority_is_preserved(self):
        nvd = SeverityInfo(
            severity="MEDIUM", cvss_score=6.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            cvss_version="3.1", source="NVD", lookup_status="resolved",
        )
        github = SeverityInfo(
            severity="CRITICAL", cvss_score=9.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_version="3.1", source="GitHub Advisory Database", lookup_status="resolved",
        )

        def lookup(identifier):
            return nvd if identifier.startswith("CVE-") else github

        with patch.object(AdvisorySeverityResolver, "_resolve_identifier", side_effect=lookup):
            first = AdvisorySeverityResolver(cache_path=self.cache_path).resolve([
                "GHSA-1234-abcd-5678", "CVE-2026-1234",
            ])
        with patch.object(
            AdvisorySeverityResolver,
            "_resolve_identifier",
            side_effect=AdvisoryLookupError("rate_limited"),
        ):
            second = AdvisorySeverityResolver(cache_path=self.cache_path).resolve([
                "CVE-2026-1234", "GHSA-1234-abcd-5678",
            ])

        self.assertEqual(first.source, "NVD")
        self.assertEqual(second.source, "NVD")
        self.assertEqual(second.data_origin, "cache")
        cache = json.loads(self.cache_path.read_text(encoding="utf-8"))
        self.assertEqual(set(cache["entries"]), {"CVE-2026-1234", "GHSA-1234-ABCD-5678"})

    @patch("cybernest.integrations.advisory_severity.urlopen")
    def test_github_403_rate_limit_headers_are_rate_limited(self, mock_urlopen):
        mock_urlopen.side_effect = HTTPError(
            "https://api.github.com/advisories/GHSA-1234-abcd-5678",
            403,
            "rate limit",
            {"X-RateLimit-Remaining": "0"},
            BytesIO(b"API rate limit exceeded"),
        )

        result = AdvisorySeverityResolver().resolve(["GHSA-1234-abcd-5678"])

        self.assertEqual(result.lookup_status, "rate_limited")

    @patch("cybernest.integrations.advisory_severity.urlopen")
    def test_github_403_retry_after_is_rate_limited(self, mock_urlopen):
        mock_urlopen.side_effect = HTTPError(
            "https://api.github.com/advisories/GHSA-1234-abcd-5678",
            403,
            "retry later",
            {"Retry-After": "60"},
            BytesIO(b"secondary rate limit"),
        )

        result = AdvisorySeverityResolver().resolve(["GHSA-1234-abcd-5678"])

        self.assertEqual(result.lookup_status, "rate_limited")

    @patch("cybernest.integrations.advisory_severity.AdvisorySeverityResolver._from_github")
    @patch("cybernest.integrations.advisory_severity.AdvisorySeverityResolver._from_nvd")
    @patch("cybernest.integrations.advisory_severity.monotonic", return_value=100.0)
    def test_rate_limited_provider_enters_bounded_cooldown_and_uses_alias_fallback(
        self, _clock, mock_nvd, mock_github
    ):
        mock_nvd.side_effect = AdvisoryLookupError(
            "rate_limited", provider="NVD", retry_after_seconds=60
        )
        mock_github.return_value = self._github_result()
        resolver = AdvisorySeverityResolver()

        result = resolver.resolve([
            "CVE-2026-1234", "CVE-2026-1235", "GHSA-1234-abcd-5678"
        ])

        self.assertEqual(mock_nvd.call_count, 1)
        self.assertEqual(mock_github.call_count, 1)
        self.assertEqual(result.source, "GitHub Advisory Database")
        self.assertIn("NVD: rate_limited", result.selection_reason)
        self.assertEqual(resolver._provider_cooldowns["NVD"], 160.0)

    def test_severity_thresholds_are_cvss_version_aware(self):
        severity = AdvisorySeverityResolver._severity_from_cvss_score

        self.assertEqual(severity(0.0, "2.0"), "LOW")
        self.assertEqual(severity(0.0, "3.1"), "NONE")
        self.assertEqual(severity(0.0, "4.0"), "NONE")
        self.assertEqual(severity(3.9, "3.1"), "LOW")
        self.assertEqual(severity(4.0, "3.1"), "MEDIUM")
        self.assertEqual(severity(7.0, "4.0"), "HIGH")
        self.assertEqual(severity(9.0, "3.1"), "CRITICAL")

    @patch("cybernest.integrations.advisory_severity.AdvisorySeverityResolver._get_json")
    def test_werkzeug_regression_advisories_use_their_valid_cvss_v3(self, mock_get_json):
        advisories = (
            ("PYSEC-2023-58", "CVE-2023-25577", "GHSA-xg9f-g7g7-2323", 7.5, "HIGH"),
            ("PYSEC-2023-221", "CVE-2023-46136", "GHSA-hrfv-mqp8-q5rw", 5.7, "MEDIUM"),
        )

        def response_for_url(url, *, accept):
            if "services.nvd.nist.gov" in url:
                cve_id = url.split("cveId=")[-1]
                return {"vulnerabilities": [{"cve": {"id": cve_id, "metrics": {}}}]}
            if "ghsa-xg9f" in url.lower():
                score, vector, label = 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "high"
            else:
                score, vector, label = 5.7, "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", "moderate"
            return {
                "severity": label,
                "cvss_severities": {"cvss_v3": {"score": score, "vector_string": vector}},
            }

        mock_get_json.side_effect = response_for_url
        for pysec_id, cve_id, ghsa_id, score, severity in advisories:
            with self.subTest(advisory=pysec_id):
                result = AdvisorySeverityResolver().resolve([pysec_id, cve_id, ghsa_id])
                self.assertEqual(result.cvss_score, score)
                self.assertEqual(result.severity, severity)
                self.assertEqual(result.cvss_version, "3.1")
                self.assertEqual(result.lookup_status, "resolved")

    @patch("cybernest.integrations.advisory_severity.urlopen")
    def test_github_403_without_rate_limit_signal_is_api_error(self, mock_urlopen):
        mock_urlopen.side_effect = HTTPError(
            "https://api.github.com/advisories/GHSA-1234-abcd-5678",
            403,
            "forbidden",
            {},
            BytesIO(b"Resource forbidden"),
        )

        result = AdvisorySeverityResolver().resolve(["GHSA-1234-abcd-5678"])

        self.assertEqual(result.lookup_status, "api_error")

    @patch("cybernest.integrations.advisory_severity.urlopen")
    def test_http_404_is_not_available_and_500_is_api_error(self, mock_urlopen):
        mock_urlopen.side_effect = HTTPError("https://example.test", 404, "missing", {}, BytesIO())
        missing = AdvisorySeverityResolver().resolve(["GHSA-1234-abcd-5678"])
        mock_urlopen.side_effect = HTTPError("https://example.test", 500, "error", {}, BytesIO())
        failed = AdvisorySeverityResolver().resolve(["CVE-2026-1234"])

        self.assertEqual(missing.lookup_status, "not_available")
        self.assertEqual(failed.lookup_status, "api_error")

    @patch("cybernest.integrations.advisory_severity.urlopen")
    def test_http_429_is_rate_limited(self, mock_urlopen):
        mock_urlopen.side_effect = HTTPError(
            "https://api.github.com/advisories/GHSA-1234-abcd-5678",
            429, "rate limited", {}, BytesIO(b"rate limited"),
        )

        result = AdvisorySeverityResolver().resolve(["GHSA-1234-abcd-5678"])

        self.assertEqual(result.lookup_status, "rate_limited")

    @patch("cybernest.integrations.advisory_severity.urlopen")
    def test_invalid_json_is_api_error(self, mock_urlopen):
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b"not json"
        mock_urlopen.return_value = response

        result = AdvisorySeverityResolver().resolve(["CVE-2026-1234"])

        self.assertEqual(result.lookup_status, "api_error")

    @patch("cybernest.integrations.advisory_severity.AdvisorySeverityResolver._get_json")
    def test_nvd_primary_is_preferred_to_github_independent_of_alias_order(self, mock_get_json):
        resolver = AdvisorySeverityResolver()
        resolver._from_github = lambda _id: self._github_result()
        resolver._from_nvd = lambda _id: self._nvd_primary_result()

        result = resolver.resolve(["GHSA-1234-abcd-5678", "CVE-2026-1234"])

        self.assertEqual(result.source, "NVD")
        self.assertEqual(result.cvss_score, 6.5)
        self.assertEqual(result.cvss_version, "3.1")

    @patch.object(AdvisorySeverityResolver, "_resolve_identifier")
    def test_selection_reason_records_the_source_policy_and_unavailable_aliases(self, mock_resolve):
        mock_resolve.side_effect = [
            SeverityInfo(
                severity="HIGH",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cvss_version="3.1",
                source="NVD",
                lookup_status="resolved",
            ),
            SeverityInfo(lookup_status="rate_limited"),
        ]

        result = AdvisorySeverityResolver().resolve(["CVE-2026-1234", "GHSA-test-1234"])

        self.assertIn("deterministic source and version priority", result.selection_reason)
        self.assertIn("GitHub: rate_limited", result.selection_reason)

    @staticmethod
    def _github_result():
        from cybernest.integrations.advisory_severity import SeverityInfo
        return SeverityInfo(severity="HIGH", cvss_score=9.0,
                            cvss_vector="CVSS:4.0/x", cvss_version="4.0",
                            source="GitHub Advisory Database", lookup_status="resolved")

    @staticmethod
    def _nvd_primary_result():
        from cybernest.integrations.advisory_severity import SeverityInfo
        return SeverityInfo(severity="MEDIUM", cvss_score=6.5,
                            cvss_vector="CVSS:3.1/x", cvss_version="3.1",
                            source="NVD", lookup_status="resolved")


if __name__ == "__main__":
    unittest.main()
