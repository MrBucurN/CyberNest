import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen
from time import monotonic

from packaging.requirements import Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from cybernest.finding import Finding
from cybernest.fixes.candidate_audit import CandidateAuditResult, PipAuditCandidateAuditor
from cybernest.fixes.compatibility import CompatibilityAnalyzer
from cybernest.fixes.index_probe import inspect_release_payload
from cybernest.fixes.models import FixPlan, FixRecommendation
from cybernest.fixes.requirements import RequirementsInput, read_requirements
from cybernest.project_discovery import DependencyManifest, ProjectDiscovery, discover_project


@dataclass(frozen=True)
class ReleaseMetadata:
    version: str
    requires_python: str
    wheel_available: bool
    python_compatible: bool | None
    yanked: bool
    source: str = "PyPI JSON API"
    checked_at: str = ""
    target_wheel_available: bool | None = None
    source_archive_available: bool = False
    matching_wheels: tuple[str, ...] = ()


class ReleaseLookupError(RuntimeError):
    def __init__(self, status: str, message: str):
        self.status = status
        super().__init__(message)


@dataclass
class _AdvisoryGroup:
    canonical_id: str
    aliases: list[str]
    findings: list[Finding]
    fix_versions: list[str]


class PyPIClient:
    """Bounded, read-only requests to the public PyPI JSON API."""

    TIMEOUT_SECONDS = 5
    CACHE_TTL_SECONDS = 900
    NOT_FOUND_TTL_SECONDS = 300

    def __init__(self):
        self._cache: dict[
            tuple[str, str, str], tuple[float, ReleaseMetadata | None]
        ] = {}
        self._versions_cache: dict[str, tuple[float, list[str]]] = {}

    def latest_versions(self, name: str, limit: int = 5) -> list[str]:
        package = canonicalize_name(name)
        cached = self._versions_cache.get(package)
        if cached and monotonic() < cached[0]:
            return list(cached[1][:limit])
        url = f"https://pypi.org/pypi/{quote(name, safe='')}/json"
        request = Request(url, headers={
            "Accept": "application/json",
            "User-Agent": "CyberNest-fix-recommendations",
        })
        try:
            with urlopen(request, timeout=self.TIMEOUT_SECONDS) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            error.close()
            status = "rate_limited" if error.code == 429 else "api_error"
            if error.code == 404:
                return []
            raise ReleaseLookupError(status, f"PyPI API returned HTTP {error.code}.") from error
        except (URLError, TimeoutError, OSError) as error:
            raise ReleaseLookupError("network_error", "Could not reach the PyPI JSON API.") from error
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ReleaseLookupError("api_error", "PyPI returned invalid JSON.") from error
        releases = payload.get("releases") if isinstance(payload, dict) else None
        if not isinstance(releases, dict):
            raise ReleaseLookupError("api_error", "PyPI response did not contain release versions.")
        parsed = []
        for value in releases:
            try:
                version = Version(value)
            except InvalidVersion:
                continue
            if version.is_prerelease or version.is_devrelease:
                continue
            parsed.append((version, str(version)))
        versions = [value for _, value in sorted(parsed, reverse=True)]
        self._versions_cache[package] = (monotonic() + self.CACHE_TTL_SECONDS, versions)
        return versions[:limit]

    def release(self, name: str, version: str, python_version: str | None) -> ReleaseMetadata | None:
        key = (canonicalize_name(name), version, python_version or "unknown")
        cached = self._cache.get(key)
        if cached:
            expires_at, value = cached
            if monotonic() < expires_at:
                return value
            self._cache.pop(key, None)
        url = f"https://pypi.org/pypi/{quote(name, safe='')}/{quote(version, safe='')}/json"
        request = Request(url, headers={
            "Accept": "application/json",
            "User-Agent": "CyberNest-fix-recommendations",
        })
        try:
            with urlopen(request, timeout=self.TIMEOUT_SECONDS) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            error.close()
            if error.code == 404:
                self._cache[key] = (
                    monotonic() + self.NOT_FOUND_TTL_SECONDS,
                    None,
                )
                return None
            status = "rate_limited" if error.code == 429 else "api_error"
            raise ReleaseLookupError(
                status, f"PyPI API returned HTTP {error.code}."
            ) from error
        except (URLError, TimeoutError, OSError) as error:
            raise ReleaseLookupError(
                "network_error", "Could not reach the PyPI JSON API."
            ) from error
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ReleaseLookupError("api_error", "PyPI returned invalid JSON.") from error
        if not isinstance(payload, dict) or not isinstance(payload.get("info"), dict):
            raise ReleaseLookupError(
                "api_error", "PyPI response did not contain release metadata."
            )

        info = payload["info"]
        requires_python = info.get("requires_python") or ""
        urls = payload.get("urls")
        urls = urls if isinstance(urls, list) else []
        available = [url for url in urls if isinstance(url, dict)]
        wheels = [
            item for item in available
            if item.get("packagetype") == "bdist_wheel" and not item.get("yanked", False)
        ]
        artifact_evidence = inspect_release_payload(payload, python_version)
        wheel_available = bool(wheels)
        yanked = bool(available) and all(item.get("yanked", False) for item in available)
        python_compatible = artifact_evidence.get("python_compatible")
        result = ReleaseMetadata(
            version=version,
            requires_python=requires_python,
            wheel_available=wheel_available,
            python_compatible=python_compatible,
            yanked=yanked,
            checked_at=datetime.now(timezone.utc).isoformat(),
            target_wheel_available=artifact_evidence.get("target_wheel_available"),
            source_archive_available=bool(artifact_evidence.get("source_archive_available")),
            matching_wheels=tuple(artifact_evidence.get("matching_wheels", [])),
        )
        self._cache[key] = (monotonic() + self.CACHE_TTL_SECONDS, result)
        return result

    @staticmethod
    def _python_compatible(requires_python: str, python_version: str) -> bool:
        if not requires_python:
            return True
        try:
            return SpecifierSet(requires_python).contains(Version(python_version))
        except (InvalidSpecifier, InvalidVersion):
            return False


class FixRecommender:
    MAX_RELEASE_LOOKUPS = 24
    MAX_CANDIDATE_AUDITS = 8
    MAX_LATEST_CANDIDATES_PER_PACKAGE = 3

    def __init__(
        self,
        pypi: PyPIClient | None = None,
        compatibility=None,
        candidate_auditor=None,
    ):
        self.pypi = pypi or PyPIClient()
        self.compatibility = compatibility or CompatibilityAnalyzer()
        self.candidate_auditor = candidate_auditor or (
            PipAuditCandidateAuditor() if isinstance(self.pypi, PyPIClient) else None
        )

    def build_plan(
        self,
        target,
        findings: list[Finding],
        python_version: str,
        current_dependencies: list[dict[str, str]] | None = None,
        python_version_override: str | None = None,
    ) -> FixPlan:
        groups: dict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            if finding.category == "dependency" and finding.affected_component:
                groups[canonicalize_name(finding.affected_component)].append(finding)

        plan = FixPlan()
        discovery = discover_project(target)
        selected_python, python_source, python_confidence, python_warnings, python_conflict = (
            self._python_target(discovery, python_version, python_version_override)
        )
        plan.python_target = selected_python or "unknown"
        plan.python_target_source = python_source
        plan.python_target_confidence = python_confidence
        plan.python_requires = discovery.requires_python
        plan.python_target_conflict = python_conflict
        plan.warnings.extend(python_warnings)
        python_version = selected_python
        if not groups:
            plan.status = "no_recommendations"
            plan.dependency_resolution = "not_needed"
            return plan

        source, requirements_error = self._compatibility_source(discovery)

        lookups = 0
        security_audits = 0
        lookup_deadline = monotonic() + 60
        for package_name, package_findings in sorted(groups.items()):
            versions = {
                item.resolved_version or item.installed_version or item.declared_specifier
                for item in package_findings
            }
            advisory_groups = self._group_advisories(package_findings)
            advisories = [item.canonical_id for item in advisory_groups]
            recommendation = FixRecommendation(
                package_name=package_findings[0].affected_component,
                installed_version=next(iter(versions)) if len(versions) == 1 else ", ".join(sorted(versions)),
                resolved_version=next(iter(versions)) if len(versions) == 1 else "",
                declared_specifier=", ".join(sorted({
                    item.declared_specifier for item in package_findings
                    if item.declared_specifier
                })),
                dependency_type=(
                    "direct" if any(item.dependency_direct is True for item in package_findings)
                    else "transitive" if all(item.dependency_direct is False for item in package_findings)
                    else "unknown"
                ),
                affected_advisories=advisories,
                advisory_aliases={item.canonical_id: item.aliases for item in advisory_groups},
                advisories=[{
                    "canonical_id": item.canonical_id,
                    "aliases": item.aliases,
                    "status": "unverified",
                } for item in advisory_groups],
            )
            plan.recommendations.append(recommendation)
            for finding in package_findings:
                recommendation.warnings.extend(finding.advisory_warnings)
            if len(versions) != 1:
                recommendation.warnings.append("Multiple installed versions were reported; manual review is required.")
                recommendation.reason = "The scan did not identify one installed version for this package."
                recommendation.unverified_advisories = advisories
                continue

            advisory_candidates = {
                version for item in advisory_groups for version in item.fix_versions
            }
            candidate_sources = {version: "advisory fix_versions" for version in advisory_candidates}
            latest_candidates = []
            latest_versions = getattr(self.pypi, "latest_versions", None)
            if callable(latest_versions) and lookups < self.MAX_RELEASE_LOOKUPS:
                try:
                    latest_candidates = latest_versions(
                        recommendation.package_name,
                        limit=self.MAX_LATEST_CANDIDATES_PER_PACKAGE,
                    )
                    lookups += 1
                except RuntimeError as error:
                    lookups += 1
                    self._add_warning(
                        recommendation.warnings,
                        f"Latest stable PyPI candidates could not be listed ({getattr(error, 'status', 'api_error')}); advisory-listed fixes remain the only candidates.",
                    )
            for latest in latest_candidates:
                if latest not in advisory_candidates:
                    candidate_sources[latest] = "latest stable PyPI releases"
            candidates = sorted(
                advisory_candidates | set(latest_candidates),
                key=lambda value: self._version_sort_key(value),
            )
            if not advisory_candidates:
                self._add_warning(
                    recommendation.warnings,
                    "No affected advisory lists a fixed version; any candidate must pass an exact-version pip-audit check before recommendation.",
                )
            valid_options = []
            validation_statuses: dict[str, str] = {}
            lookup_limit_reached = False
            for candidate in candidates:
                try:
                    parsed = Version(candidate)
                except InvalidVersion:
                    validation_statuses[candidate] = "invalid_version"
                    recommendation.candidate_validations.append({
                        "version": candidate,
                        "source": "advisory fix_versions",
                        "status": "invalid_version",
                    })
                    continue
                if parsed.is_prerelease or parsed.is_devrelease:
                    validation_statuses[candidate] = "skipped_prerelease"
                    recommendation.candidate_validations.append({
                        "version": candidate,
                        "source": "advisory fix_versions",
                        "status": "skipped_prerelease",
                    })
                    continue
                if len(versions) == 1:
                    try:
                        if parsed == Version(next(iter(versions))):
                            validation_statuses[candidate] = "already_installed"
                            recommendation.candidate_validations.append({
                                "version": candidate,
                                "source": candidate_sources.get(candidate, "PyPI JSON API"),
                                "status": "already_installed",
                            })
                            continue
                    except InvalidVersion:
                        pass
                if lookups >= self.MAX_RELEASE_LOOKUPS or monotonic() >= lookup_deadline:
                    lookup_limit_reached = True
                    break
                try:
                    release = self.pypi.release(
                        recommendation.package_name, candidate, python_version
                    )
                except RuntimeError as error:
                    lookups += 1
                    validation_status = getattr(error, "status", "network_error")
                    validation_statuses[candidate] = validation_status
                    recommendation.candidate_validations.append({
                        "version": candidate,
                        "source": "PyPI JSON API",
                        "status": validation_status,
                        "error": str(error),
                    })
                    self._add_warning(
                        recommendation.warnings,
                        f"PyPI validation for candidate {candidate} failed ({validation_status}): {error}; that candidate is unverified.",
                    )
                    continue
                lookups += 1
                if release is None:
                    validation_statuses[candidate] = "not_found"
                    recommendation.candidate_validations.append({
                        "version": candidate,
                        "source": "PyPI JSON API",
                        "status": "not_found",
                    })
                    continue
                status = "verified"
                if release.yanked:
                    status = "yanked"
                elif release.target_wheel_available is False or not release.wheel_available:
                    status = "no_wheel"
                elif release.python_compatible is None:
                    status = "python_target_unknown"
                elif not release.python_compatible:
                    status = "python_incompatible"
                elif release.target_wheel_available is None:
                    status = "target_wheel_unknown"
                validation_statuses[candidate] = status
                recommendation.candidate_validations.append({
                    "version": candidate,
                    "source": candidate_sources.get(candidate, release.source),
                    "status": status,
                    "checked_at": release.checked_at,
                    "requires_python": release.requires_python,
                    "yanked": release.yanked,
                    "wheel_available": release.wheel_available,
                    "target_wheel_available": release.target_wheel_available,
                    "source_archive_available": release.source_archive_available,
                    "matching_wheels": list(release.matching_wheels),
                    "python_compatible": release.python_compatible,
                })
                if status != "verified":
                    if status == "python_incompatible":
                        warning = f"Candidate {candidate} requires Python {release.requires_python}, which excludes {python_version}."
                    elif status == "python_target_unknown":
                        warning = "Candidate release exists, but no single project Python target is known for wheel compatibility validation."
                    elif status == "target_wheel_unknown":
                        warning = "Candidate release exists, but target-platform wheel compatibility could not be established."
                    elif status == "yanked":
                        warning = f"Candidate {candidate} is yanked on PyPI."
                    else:
                        warning = f"Candidate {candidate} has no non-yanked wheel; source builds are disabled for safety."
                    self._add_warning(recommendation.warnings, warning)
                    continue
                addressed_indexes = [
                    i for i, advisory in enumerate(advisory_groups)
                    if candidate in advisory.fix_versions
                ]
                valid_options.append((len(addressed_indexes), parsed, candidate, addressed_indexes, release))
                validation = next((
                    item for item in reversed(recommendation.candidate_validations)
                    if item.get("version") == candidate and item.get("status") == "verified"
                ), None)
                if validation is not None:
                    validation["advisory_fixed"] = [
                        advisory_groups[index].canonical_id for index in addressed_indexes
                    ]
                    validation["advisory_coverage_status"] = (
                        "complete" if len(addressed_indexes) == len(advisory_groups)
                        else "partial" if addressed_indexes
                        else "none"
                    )

            if lookup_limit_reached:
                self._add_warning(
                    recommendation.warnings,
                    "PyPI candidate lookup limit or time budget was reached; unchecked candidates remain unverified.",
                )
                for candidate in candidates:
                    if candidate not in validation_statuses:
                        validation_statuses[candidate] = "not_checked"
                        recommendation.candidate_validations.append({
                            "version": candidate,
                            "source": "PyPI JSON API",
                            "status": "not_checked",
                        })

            if not valid_options:
                inconclusive_statuses = {
                    "network_error", "rate_limited", "api_error", "not_checked",
                    "python_target_unknown", "target_wheel_unknown",
                }
                for index, advisory in enumerate(advisory_groups):
                    statuses_for_advisory = {
                        validation_statuses.get(version, "not_checked")
                        for version in advisory.fix_versions
                    }
                    target = recommendation.unverified_advisories if statuses_for_advisory & inconclusive_statuses else recommendation.remaining_advisories
                    target.append(advisory.canonical_id)
                recommendation.recommendation_status = (
                    "no_known_fix" if not any(item.fix_versions for item in advisory_groups)
                    else "requires_manual_review"
                )
                recommendation.security_coverage_status = (
                    "unverified" if recommendation.unverified_advisories else "unresolved"
                )
                recommendation.release_validation_status = (
                    "unverified" if recommendation.unverified_advisories else "no_verified_candidate"
                )
                recommendation.reason = "No advisory-listed stable release was verified for this Python target and resolver policy."
                self._set_advisory_statuses(recommendation, "remaining", "unverified")
                continue

            valid_options.sort(key=lambda option: (-option[0], option[1]))
            _, _, candidate, addressed_indexes, release = valid_options[0]
            recommendation.suggested_version = candidate
            recommendation.requires_python = release.requires_python
            recommendation.release_validation_status = "verified"
            recommendation.addressed_advisories = [
                advisory_groups[index].canonical_id for index in addressed_indexes
            ]
            for index, advisory in enumerate(advisory_groups):
                if index in addressed_indexes:
                    continue
                states = {
                    validation_statuses.get(version, "not_checked")
                    for version in advisory.fix_versions
                }
                if states & {"network_error", "rate_limited", "api_error", "not_checked"}:
                    recommendation.unverified_advisories.append(advisory.canonical_id)
                else:
                    recommendation.remaining_advisories.append(advisory.canonical_id)
            recommendation.security_coverage_status = (
                "complete" if len(recommendation.addressed_advisories) == len(advisory_groups)
                else "partial"
            )
            self._set_advisory_statuses(recommendation, "remaining", "unverified")
            for advisory in recommendation.advisories:
                if advisory["canonical_id"] in recommendation.addressed_advisories:
                    advisory["status"] = "addressed"
            recommendation.recommendation_status = (
                "recommended"
                if recommendation.security_coverage_status == "complete"
                else "partial"
            )
            recommendation.reason = (
                f"PyPI validated release {candidate} for Python {python_version}. "
                f"The advisory explicitly lists this version for {len(recommendation.addressed_advisories)} "
                f"of {len(advisory_groups)} canonical security advisories."
            )
            security_audits = self._audit_candidate_options(
                recommendation,
                advisory_groups,
                valid_options,
                security_audits,
                lookup_deadline,
            )
            if source:
                self._add_requirement_warning(
                    recommendation, source, package_name, recommendation.suggested_version
                )
            if recommendation.remaining_advisories:
                recommendation.warnings.append("This update does not resolve all known findings.")
            if recommendation.unverified_advisories:
                recommendation.warnings.append("Some advisory fix candidates could not be validated.")
            recommendation.warnings.append("Dependency compatibility and application runtime behavior are separate checks.")
            recommendation.warnings = self._unique(recommendation.warnings)

        if requirements_error:
            plan.warnings.append(requirements_error)
            for item in plan.recommendations:
                if item.suggested_version:
                    item.compatibility_status = "unknown"
        elif python_version is None:
            plan.warnings.append(
                "No single Python target can be selected from the project's declared range; pass --python-version to check one target."
            )
            plan.dependency_resolution = "not_run"
            plan.dependency_resolution_status = "python_target_unknown"
            for item in plan.recommendations:
                item.compatibility_status = "unknown"
        elif python_conflict:
            plan.warnings.append("Compatibility was not run because the selected Python target conflicts with project metadata.")
            plan.dependency_resolution = "not_run"
            plan.dependency_resolution_status = "python_target_conflict"
            for item in plan.recommendations:
                if item.suggested_version:
                    item.compatibility_status = "unknown"
        elif source:
            if current_dependencies is None:
                self.compatibility.analyze(source, plan, python_version)
            else:
                self.compatibility.analyze(
                    source, plan, python_version, current_dependencies=current_dependencies
                )

        plan.warnings = self._unique(plan.warnings)
        for item in plan.recommendations:
            item.warnings = self._unique(item.warnings)

        statuses = {item.compatibility_status for item in plan.recommendations if item.suggested_version}
        has_unaddressed = any(item.recommendation_status != "recommended" for item in plan.recommendations)
        if plan.recommendations and all(
            item.recommendation_status == "no_known_fix"
            for item in plan.recommendations
        ):
            plan.status = "no_known_fix"
            return plan
        if "incompatible" in statuses:
            plan.status = "conflict"
        elif "unknown" in statuses or has_unaddressed:
            plan.status = "partial"
        elif statuses == {"compatible"}:
            plan.status = "ready_for_review"
        else:
            plan.status = "partial"
        return plan

    def _audit_candidate_options(
        self,
        recommendation: FixRecommendation,
        advisory_groups: list[_AdvisoryGroup],
        valid_options: list[tuple[int, Version, str, list[int], ReleaseMetadata]],
        audit_count: int,
        deadline: float,
    ) -> int:
        if not valid_options:
            return audit_count

        has_advisory_fixed_candidate = any(option[3] for option in valid_options)
        if not self.candidate_auditor:
            if not has_advisory_fixed_candidate:
                self._mark_candidate_manual_review(
                    recommendation,
                    "No advisory-listed fix candidate passed validation, and exact-version security auditing is unavailable.",
                )
            return audit_count

        latest_versions = {
            str(item.get("version"))
            for item in recommendation.candidate_validations
            if item.get("source") == "latest stable PyPI releases"
            and item.get("status") == "verified"
        }
        valid_options = sorted(valid_options, key=lambda option: option[1], reverse=True)
        preferred = [option for option in valid_options if option[2] in latest_versions]
        preferred.extend(option for option in valid_options if option not in preferred)
        selected_results = []
        attempts_for_package = 0
        for _, parsed, candidate, _, release in preferred:
            if audit_count >= self.MAX_CANDIDATE_AUDITS or monotonic() >= deadline:
                break
            if attempts_for_package >= self.MAX_LATEST_CANDIDATES_PER_PACKAGE:
                break
            attempts_for_package += 1
            audit_count += 1
            try:
                audit = self.candidate_auditor.audit(
                    recommendation.package_name, candidate
                )
            except Exception as error:
                audit = CandidateAuditResult(
                    "audit_error", recommendation.package_name, candidate,
                    error=type(error).__name__,
                )
            validation = next((
                item for item in recommendation.candidate_validations
                if item.get("version") == candidate
            ), None)
            if validation is not None:
                validation["candidate_security_audit"] = {
                    "status": audit.status,
                    "source": "pip-audit exact-pin audit",
                    "advisories": [
                        item.get("id") for item in audit.advisories
                        if isinstance(item.get("id"), str)
                    ],
                    "error": audit.error,
                }
            if audit.status != "verified":
                self._add_warning(
                    recommendation.warnings,
                    f"Candidate security audit for {candidate} was not conclusive ({audit.status}).",
                )
                continue
            remaining, new_advisories = self._candidate_advisory_coverage(
                advisory_groups, audit.advisories
            )
            if validation is not None:
                validation["candidate_security_audit"]["remaining_advisories"] = remaining
                validation["candidate_security_audit"]["new_advisories"] = new_advisories
                validation["candidate_security_audit"]["coverage_status"] = (
                    "complete" if not remaining and not new_advisories else "partial"
                )
            selected_results.append((
                len(remaining) + len(new_advisories),
                parsed,
                candidate,
                audit,
                remaining,
                new_advisories,
                release,
            ))
            if not remaining and not new_advisories:
                break

        if not selected_results:
            if attempts_for_package:
                recommendation.candidate_audit_status = "unverified"
            if not has_advisory_fixed_candidate:
                self._mark_candidate_manual_review(
                    recommendation,
                    "No advisory-listed fix candidate passed validation, and no latest candidate received a conclusive exact-version security audit.",
                )
            return audit_count

        selected_results.sort(key=lambda item: item[2], reverse=True)
        selected_results.sort(key=lambda item: item[0])
        _, _, candidate, audit, remaining, new_advisories, release = selected_results[0]
        recommendation.suggested_version = candidate
        recommendation.requires_python = release.requires_python
        recommendation.candidate_audit_status = "verified"
        recommendation.candidate_audit_source = "pip-audit exact-pin audit"
        recommendation.new_advisories = list(new_advisories)
        remaining_set = set(remaining)
        recommendation.remaining_advisories = [
            group.canonical_id for group in advisory_groups
            if group.canonical_id in remaining_set
        ]
        recommendation.addressed_advisories = [
            group.canonical_id for group in advisory_groups
            if group.canonical_id not in remaining_set
        ]
        recommendation.unverified_advisories = []
        recommendation.security_coverage_status = (
            "complete" if not remaining and not new_advisories else "partial"
        )
        recommendation.recommendation_status = (
            "recommended" if recommendation.security_coverage_status == "complete" else "partial"
        )
        recommendation.reason = (
            f"pip-audit checked {recommendation.package_name}=={candidate} against its current advisory database and "
            + ("reported no known vulnerabilities." if not remaining and not new_advisories
               else f"reported {len(remaining) + len(new_advisories)} remaining or additional advisories.")
        )
        recommendation.advisories = [
            {
                "canonical_id": group.canonical_id,
                "aliases": group.aliases,
                "status": "remaining" if group.canonical_id in remaining_set else "addressed",
            }
            for group in advisory_groups
        ]
        if remaining or new_advisories:
            recommendation.suggested_version = None
            recommendation.recommendation_status = "requires_manual_review"
            recommendation.reason += " No update is recommended because this candidate is not clear of reported advisories."
        return audit_count

    @staticmethod
    def _mark_candidate_manual_review(
        recommendation: FixRecommendation,
        reason: str,
    ) -> None:
        recommendation.suggested_version = None
        recommendation.recommendation_status = "requires_manual_review"
        recommendation.security_coverage_status = "unverified"
        recommendation.release_validation_status = "unverified"
        recommendation.addressed_advisories = []
        recommendation.remaining_advisories = []
        recommendation.unverified_advisories = list(recommendation.affected_advisories)
        for advisory in recommendation.advisories:
            advisory["status"] = "unverified"
        recommendation.reason = reason
        FixRecommender._add_warning(
            recommendation.warnings,
            "No update candidate is recommended without evidence that it resolves the reported security issues.",
        )

    @classmethod
    def _candidate_advisory_coverage(
        cls,
        baseline: list[_AdvisoryGroup],
        candidate_advisories: list[dict[str, object]],
    ) -> tuple[list[str], list[str]]:
        baseline_aliases = {}
        for group in baseline:
            for identifier in (group.canonical_id, *group.aliases):
                baseline_aliases[identifier.upper()] = group.canonical_id
        candidate_findings = []
        for item in candidate_advisories:
            identifier = item.get("id")
            aliases = item.get("aliases", [])
            ids = [identifier] if isinstance(identifier, str) else []
            if isinstance(aliases, list):
                ids.extend(value for value in aliases if isinstance(value, str))
            if not ids:
                continue
            candidate_findings.append(Finding(
                title=ids[0],
                severity="UNKNOWN",
                tool="pip-audit",
                category="dependency",
                advisory_ids=ids,
                affected_component="candidate",
            ))
        discovered = cls._group_advisories(candidate_findings)
        remaining = set()
        new_advisories = []
        for group in discovered:
            matched = {
                baseline_aliases[identifier.upper()]
                for identifier in (group.canonical_id, *group.aliases)
                if identifier.upper() in baseline_aliases
            }
            if matched:
                remaining.update(matched)
            else:
                new_advisories.append(group.canonical_id)
        return sorted(remaining), sorted(new_advisories)

    @staticmethod
    def _fixes_for(finding: Finding) -> list[str]:
        values = [*finding.fixed_version.split(","), *finding.additional_fix_versions]
        result = []
        for value in values:
            value = value.strip()
            if not value:
                continue
            try:
                normalized = str(Version(value))
            except InvalidVersion:
                continue
            if normalized not in result:
                result.append(normalized)
        return result

    @classmethod
    def _group_advisories(cls, findings: list[Finding]) -> list[_AdvisoryGroup]:
        groups: list[dict[str, object]] = []
        for finding in findings:
            identifiers = {
                value.strip().upper()
                for value in [*finding.advisory_ids, finding.title]
                if isinstance(value, str) and value.strip()
            }
            if not identifiers:
                identifiers = {"UNKNOWN-" + str(len(groups) + 1)}
            matched = [group for group in groups if identifiers & group["ids"]]
            if not matched:
                groups.append({"ids": identifiers, "findings": [finding]})
                continue
            primary = matched[0]
            primary["ids"].update(identifiers)
            primary["findings"].append(finding)
            for extra in matched[1:]:
                primary["ids"].update(extra["ids"])
                primary["findings"].extend(extra["findings"])
                groups.remove(extra)
            changed = True
            while changed:
                changed = False
                for other in list(groups):
                    if other is primary or not (primary["ids"] & other["ids"]):
                        continue
                    primary["ids"].update(other["ids"])
                    primary["findings"].extend(other["findings"])
                    groups.remove(other)
                    changed = True

        result = []
        for group in groups:
            identifiers = sorted(group["ids"], key=cls._canonical_id_priority)
            canonical_id = identifiers[0]
            group_findings = list(group["findings"])
            fix_versions = []
            for finding in group_findings:
                for version in cls._fixes_for(finding):
                    if version not in fix_versions:
                        fix_versions.append(version)
            result.append(_AdvisoryGroup(
                canonical_id=canonical_id,
                aliases=sorted(value for value in identifiers[1:]),
                findings=group_findings,
                fix_versions=fix_versions,
            ))
        return sorted(result, key=lambda item: item.canonical_id)

    @staticmethod
    def _canonical_id_priority(value: str) -> tuple[int, str]:
        if value.startswith("CVE-"):
            priority = 0
        elif value.startswith("GHSA-"):
            priority = 1
        elif value.startswith("PYSEC-"):
            priority = 2
        else:
            priority = 3
        return priority, value

    @staticmethod
    def _set_advisory_statuses(recommendation, default_status, unverified_status):
        remaining = set(recommendation.remaining_advisories)
        unverified = set(recommendation.unverified_advisories)
        for advisory in recommendation.advisories:
            canonical_id = advisory["canonical_id"]
            if canonical_id in recommendation.addressed_advisories:
                advisory["status"] = "addressed"
            elif canonical_id in unverified:
                advisory["status"] = unverified_status
            elif canonical_id in remaining:
                advisory["status"] = default_status

    @staticmethod
    def _unique(values: list[str]) -> list[str]:
        return list(dict.fromkeys(value for value in values if value))

    @staticmethod
    def _add_warning(warnings: list[str], warning: str) -> None:
        if warning and warning not in warnings:
            warnings.append(warning)

    @staticmethod
    def _add_requirement_warning(recommendation, source, package_name, candidate):
        current_constraints = [
            req.specifier for _, req in source.requirements
            if canonicalize_name(req.name) == package_name
        ]
        for constraint in current_constraints:
            if constraint and not constraint.contains(candidate, prereleases=False):
                recommendation.warnings.append(
                    f"Existing requirement {constraint} must be changed to apply this fix; CyberNest did not edit it."
                )
                return
        if not current_constraints:
            recommendation.warnings.append(
                "This package is transitive; applying the suggestion may require adding an explicit requirement."
            )

    @staticmethod
    def _python_target(
        discovery: ProjectDiscovery,
        runtime_version: str,
        override: str | None,
    ) -> tuple[str | None, str, str, list[str], bool]:
        warnings: list[str] = []
        conflict = discovery.python_target_conflict
        if override:
            selected = str(Version(override))
            source, confidence = "cli", "explicit"
            warnings.append(f"Compatibility target Python version was explicitly set to {selected}.")
            if discovery.python_target and discovery.python_target != selected:
                warnings.append(
                    f"CLI Python target {selected} overrides project target {discovery.python_target}."
                )
            if discovery.requires_python:
                try:
                    if not SpecifierSet(discovery.requires_python).contains(Version(selected)):
                        conflict = True
                        warnings.append(
                            f"Selected Python {selected} is outside project requires-python {discovery.requires_python}."
                        )
                except (InvalidSpecifier, InvalidVersion):
                    conflict = True
                    warnings.append("Project requires-python metadata is invalid; compatibility is unknown.")
            return selected, source, confidence, warnings, conflict

        if discovery.python_target:
            selected = discovery.python_target
            if conflict:
                warnings.append("The declared Python target conflicts with project requires-python metadata.")
            return (
                selected,
                discovery.python_target_source or "project metadata",
                discovery.python_target_confidence,
                warnings,
                conflict,
            )

        if discovery.requires_python:
            warnings.append(
                f"Project declares Python range {discovery.requires_python}; no single target was inferred."
            )
            return None, "requires-python metadata", "range", warnings, conflict

        warnings.extend(discovery.warnings)
        warnings.append(
            f"No Python target was declared; compatibility uses the running interpreter ({runtime_version}) as an assumption."
        )
        return runtime_version, "runtime interpreter", "assumed", warnings, conflict

    @staticmethod
    def _compatibility_source(
        discovery: ProjectDiscovery,
    ) -> tuple[RequirementsInput | None, str]:
        manifests = [manifest for manifest in discovery.manifests if not manifest.unsupported_reason]
        if discovery.unsupported_files:
            return None, "Some dependency manifests are unsupported; project-wide compatibility is unknown."
        if not manifests:
            return None, "No supported dependency manifest was found for compatibility analysis."
        if len(manifests) != 1:
            return None, "Multiple dependency files or optional groups require separate compatibility plans."
        manifest = manifests[0]
        if manifest.format == "requirements":
            try:
                source = read_requirements(manifest.path)
            except (OSError, UnicodeError) as error:
                return None, f"Could not read {manifest.label}: {error}"
            return source, source.unsupported_reason
        parsed = []
        try:
            for index, value in enumerate(manifest.requirements):
                parsed.append((index, Requirement(value)))
        except Exception:
            return None, f"{manifest.label} contains unsupported dependency syntax."
        return RequirementsInput(manifest.path, list(manifest.requirements), parsed), ""

    @staticmethod
    def _version_sort_key(value: str):
        try:
            return (0, Version(value))
        except InvalidVersion:
            return (1, Version("0"))
