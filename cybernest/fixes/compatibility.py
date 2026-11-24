import json
import os
import re
import subprocess
import sys
import tempfile
from itertools import islice, product
from pathlib import Path

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from cybernest.fixes.models import FixPlan
from cybernest.fixes.index_probe import probe_pypi_release
from cybernest.fixes.requirements import RequirementsInput, rewrite_for_candidates


class CompatibilityAnalyzer:
    """Resolve a proposed requirements set without installing packages."""

    MAX_REQUIREMENTS = 150
    TIMEOUT_SECONDS = 75
    MAX_COMBINATION_ATTEMPTS = 4

    def analyze(
        self,
        source: RequirementsInput,
        plan: FixPlan,
        python_version: str,
        current_dependencies: list[dict[str, str]] | None = None,
    ) -> None:
        candidates = {
            canonicalize_name(item.package_name): item.suggested_version
            for item in plan.recommendations
            if item.suggested_version
        }
        if not candidates:
            plan.dependency_resolution = "not_run"
            for item in plan.recommendations:
                item.compatibility_status = "unknown"
            return
        if source.unsupported_reason:
            plan.warnings.append(source.unsupported_reason)
            self._set_status(plan, "unknown", "not_run")
            return
        if len(source.requirements) > self.MAX_REQUIREMENTS:
            plan.warnings.append("Requirements file exceeds the compatibility analysis limit.")
            self._set_status(plan, "unknown", "not_run")
            return

        candidate_sets = self._candidate_sets(plan, candidates)
        attempts = []
        with tempfile.TemporaryDirectory(prefix="cybernest-fix-plan-") as temp_dir:
            work = Path(temp_dir)
            candidate_file = work / "requirements.txt"
            report_file = work / "pip-report.json"
            command = [
                sys.executable, "-m", "pip", "install",
                "--dry-run", "--ignore-installed", "--report", str(report_file),
                "--index-url", "https://pypi.org/simple",
                "--only-binary=:all:", "--no-input", "--disable-pip-version-check",
                "--timeout", "5", "--retries", "0",
                "--python-version", python_version,
                "--requirement", str(candidate_file),
            ]
            env = {
                key: value for key, value in os.environ.items()
                if not key.upper().startswith("PIP_")
            }
            env["PIP_CONFIG_FILE"] = os.devnull
            result = None
            for index, candidate_set in enumerate(candidate_sets):
                candidate_file.write_text(
                    "\n".join(rewrite_for_candidates(source, candidate_set)) + "\n",
                    encoding="utf-8",
                )
                try:
                    result = subprocess.run(
                        command,
                        cwd=work,
                        capture_output=True,
                        text=True,
                        timeout=self.TIMEOUT_SECONDS,
                        check=False,
                        env=env,
                    )
                except (OSError, subprocess.TimeoutExpired) as error:
                    plan.warnings.append(f"Dependency resolution did not complete: {error}")
                    detail = "timeout" if isinstance(error, subprocess.TimeoutExpired) else "process_error"
                    self._set_status(plan, "unknown", "failed", detail)
                    plan.dependency_resolution_evidence = {
                        "resolver": "pip install --dry-run",
                        "python_target": python_version,
                        "candidate_attempts": attempts,
                    }
                    return
                diagnostic = (result.stderr or result.stdout).strip()
                _, detail = self._classify_resolver_failure(diagnostic) if result.returncode else ("compatible", "resolved")
                attempts.append({
                    "candidates": dict(candidate_set),
                    "returncode": result.returncode,
                    "detail": detail,
                })
                if result.returncode == 0:
                    candidates = candidate_set
                    self._apply_selected_candidates(plan, candidates)
                    break
                if detail != "dependency_conflict" or index + 1 >= len(candidate_sets):
                    break
            if result is None:
                plan.warnings.append("No candidate combination was available for dependency resolution.")
                self._set_status(plan, "unknown", "not_run", "no_candidate_combination")
                return
            if len(attempts) > 1:
                plan.warnings.append(
                    f"The initial candidate set conflicted; pip checked {len(attempts)} bounded candidate combinations."
                )

            if result.returncode != 0:
                diagnostic = (result.stderr or result.stdout).strip()
                status, detail = self._classify_resolver_failure(diagnostic)
                distribution_evidence = None
                if detail == "no_compatible_binary_or_index_release":
                    distribution_evidence = self._probe_missing_distribution(
                        diagnostic, python_version
                    )
                    if distribution_evidence:
                        probe_status = distribution_evidence.get("status")
                        if probe_status == "not_found":
                            detail = "release_not_found_on_public_pypi"
                        elif probe_status == "available":
                            if distribution_evidence.get("python_compatible") is False:
                                status, detail = "incompatible", "python_incompatible"
                            elif distribution_evidence.get("target_wheel_available") is False:
                                detail = "no_compatible_wheel_for_target"
                            else:
                                detail = "no_matching_distribution_unclassified"
                if detail == "no_compatible_binary_or_index_release":
                    message = (
                        "pip found no matching binary distribution for this target. "
                        "This may be a platform/Python wheel gap or a missing index release; "
                        "source builds are disabled for safety, so compatibility is unknown."
                    )
                elif detail == "no_compatible_wheel_for_target":
                    source_note = (
                        "A source archive exists, but source builds are disabled; "
                        "its buildability was not tested."
                        if distribution_evidence.get("source_archive_available")
                        else "No source archive was listed for this release."
                    )
                    package = distribution_evidence.get("package", "The requested package")
                    version = distribution_evidence.get("version", "")
                    package_version = f"{package}=={version}" if version else str(package)
                    next_step = (
                        "Try the target's matching Python/platform, or review the release in an isolated environment."
                    )
                    message = (
                        f"{package_version} has no compatible binary wheel for Python {python_version} "
                        f"on this platform. {source_note} Compatibility remains UNKNOWN. {next_step}"
                    )
                elif detail == "release_not_found_on_public_pypi":
                    message = (
                        "The requested package release is not listed on public PyPI; "
                        "compatibility remains unknown."
                    )
                elif detail == "no_matching_distribution_unclassified":
                    message = (
                        "The package release exists on public PyPI, but the resolver failure "
                        "was not explained by target wheel or Requires-Python metadata; compatibility is unknown."
                    )
                elif detail == "network_error":
                    message = "The package index could not be reached; compatibility is unknown."
                elif detail == "index_error":
                    message = "The package index returned an access or service error; compatibility is unknown."
                elif detail == "python_incompatible":
                    message = "The resolver reports a Python version conflict."
                elif detail == "dependency_conflict":
                    message = "The resolver confirmed conflicting package requirements."
                else:
                    message = "The resolver failed without enough evidence to classify compatibility."
                plan.warnings.append(message)
                plan.dependency_resolution_evidence = {
                    "resolver": "pip install --dry-run",
                    "index": "https://pypi.org/simple",
                    "python_target": python_version,
                    "binary_only": True,
                    "status": status,
                    "detail": detail,
                    "diagnostic": diagnostic[-900:],
                    "distribution_probe": distribution_evidence or {},
                    "candidate_attempts": attempts,
                }
                self._set_status(plan, status, "failed", detail)
                return

            try:
                report = json.loads(report_file.read_text(encoding="utf-8"))
                installs = report["install"]
                if not isinstance(installs, list):
                    raise ValueError("pip install report has no package list")
                selected = {}
                for entry in installs:
                    metadata = entry["metadata"]
                    name, version = metadata["name"], metadata["version"]
                    if not isinstance(name, str) or not name or not isinstance(version, str):
                        raise ValueError("pip install report has invalid package metadata")
                    Version(version)
                    selected[canonicalize_name(name)] = version
            except (OSError, ValueError, KeyError, TypeError):
                plan.warnings.append("pip reported success but its resolution report was unusable.")
                self._set_status(plan, "unknown", "failed", "invalid_report")
                return

            missing = []
            for name, version in candidates.items():
                actual = selected.get(name)
                try:
                    confirmed = actual is not None and Version(actual) == Version(version)
                except InvalidVersion:
                    confirmed = False
                if not confirmed:
                    missing.append(name)
            if missing:
                plan.warnings.append(
                    "pip's report did not confirm the requested candidate(s): "
                    + ", ".join(missing)
                )
                self._set_status(plan, "unknown", "unconfirmed", "candidate_not_confirmed")
                return

            if current_dependencies is None:
                plan.warnings.append(
                    "Current package inventory is unavailable; dependency changes cannot be verified."
                )
                self._set_status(plan, "unknown", "resolved", "inventory_unavailable")
                return

            current = {}
            try:
                if not isinstance(current_dependencies, list):
                    raise ValueError("package inventory is not a list")
                for item in current_dependencies:
                    if (
                        not isinstance(item, dict)
                        or not isinstance(item.get("name"), str)
                        or not item.get("name")
                        or not isinstance(item.get("version"), str)
                    ):
                        raise ValueError("package inventory has invalid entries")
                    name = canonicalize_name(item["name"])
                    version = item["version"]
                    Version(version)
                    if name in current and Version(current[name]) != Version(version):
                        raise ValueError(f"multiple installed versions were reported for {name}")
                    current[name] = version
            except (InvalidVersion, TypeError, ValueError) as error:
                plan.warnings.append(f"Current package inventory is unusable: {error}")
                self._set_status(plan, "unknown", "unconfirmed", "invalid_inventory")
                return
            changes = []
            for name in sorted(set(current) | set(selected)):
                previous_version = current.get(name)
                selected_version = selected.get(name)
                if previous_version is not None and selected_version is not None:
                    try:
                        unchanged = Version(previous_version) == Version(selected_version)
                    except InvalidVersion:
                        unchanged = previous_version == selected_version
                    if unchanged:
                        continue
                    change = "updated"
                elif previous_version is None:
                    change = "added"
                else:
                    change = "removed"
                changes.append({
                    "package_name": name,
                    "previous_version": previous_version,
                    "selected_version": selected_version,
                    "change": change,
                })
            plan.dependency_changes = changes
            plan.dependency_resolution_evidence = {
                "resolver": "pip install --dry-run",
                "index": "https://pypi.org/simple",
                "python_target": python_version,
                "binary_only": True,
                "status": "resolved",
                "selected_dependency_count": len(selected),
                "candidate_attempts": attempts,
            }
            self._set_status(plan, "compatible", "resolved", "resolved")

    @classmethod
    def _candidate_sets(
        cls,
        plan: FixPlan,
        primary: dict[str, str],
    ) -> list[dict[str, str]]:
        choices = {}
        for recommendation in plan.recommendations:
            name = canonicalize_name(recommendation.package_name)
            if name not in primary:
                continue
            options = [primary[name]]
            alternatives = set()
            for validation in recommendation.candidate_validations:
                version = validation.get("version")
                if validation.get("status") != "verified" or not isinstance(version, str):
                    continue
                audit = validation.get("candidate_security_audit")
                if isinstance(audit, dict) and audit.get("status") == "verified":
                    eligible = audit.get("coverage_status") == "complete"
                else:
                    eligible = validation.get("advisory_coverage_status") in {"complete", "partial"}
                if eligible and version != primary[name]:
                    alternatives.add(version)
            options.extend(sorted(alternatives, key=cls._version_sort_key, reverse=True))
            choices[name] = options

        if not choices:
            return [dict(primary)]
        keys = sorted(choices)
        result = []
        seen = set()
        for values in islice(product(*(choices[key] for key in keys)), cls.MAX_COMBINATION_ATTEMPTS):
            candidate_set = dict(zip(keys, values))
            signature = tuple(sorted(candidate_set.items()))
            if signature in seen:
                continue
            seen.add(signature)
            result.append(candidate_set)
        return result or [dict(primary)]

    @staticmethod
    def _version_sort_key(value: str):
        try:
            return (0, Version(value))
        except InvalidVersion:
            return (1, Version("0"))

    @staticmethod
    def _apply_selected_candidates(plan: FixPlan, candidates: dict[str, str]) -> None:
        for recommendation in plan.recommendations:
            name = canonicalize_name(recommendation.package_name)
            selected = candidates.get(name)
            if selected is None or selected == recommendation.suggested_version:
                continue
            validation = next((
                item for item in recommendation.candidate_validations
                if item.get("version") == selected and item.get("status") == "verified"
            ), None)
            if validation is None:
                continue
            recommendation.suggested_version = selected
            recommendation.requires_python = str(validation.get("requires_python", ""))
            recommendation.release_validation_status = "verified"
            audit = validation.get("candidate_security_audit")
            if isinstance(audit, dict) and audit.get("status") == "verified":
                recommendation.candidate_audit_status = "verified"
                recommendation.candidate_audit_source = str(audit.get("source", "pip-audit exact-pin audit"))
                recommendation.addressed_advisories = list(recommendation.affected_advisories)
                recommendation.remaining_advisories = []
                recommendation.unverified_advisories = []
                recommendation.new_advisories = []
                recommendation.security_coverage_status = "complete"
                recommendation.recommendation_status = "recommended"
            else:
                recommendation.candidate_audit_status = (
                    str(audit.get("status", "unverified")) if isinstance(audit, dict) else "not_run"
                )
                recommendation.candidate_audit_source = (
                    str(audit.get("source", "pip-audit exact-pin audit"))
                    if isinstance(audit, dict) else ""
                )
                addressed = validation.get("advisory_fixed", [])
                addressed = addressed if isinstance(addressed, list) else []
                recommendation.addressed_advisories = list(addressed)
                recommendation.remaining_advisories = [
                    item for item in recommendation.affected_advisories
                    if item not in recommendation.addressed_advisories
                ]
                recommendation.unverified_advisories = []
                recommendation.new_advisories = []
                recommendation.security_coverage_status = (
                    "complete" if not recommendation.remaining_advisories else "partial"
                )
                recommendation.recommendation_status = (
                    "recommended" if not recommendation.remaining_advisories else "partial"
                )
            for advisory in recommendation.advisories:
                advisory["status"] = (
                    "addressed" if advisory.get("canonical_id") in recommendation.addressed_advisories
                    else "remaining"
                )
            recommendation.reason += (
                f" Project-wide resolver selected the compatible alternative {selected}."
            )

    @staticmethod
    def _probe_missing_distribution(
        diagnostic: str, python_version: str
    ) -> dict[str, object] | None:
        patterns = (
            r"No matching distribution found for\s+([A-Za-z0-9_.-]+)==([^\s;]+)",
            r"requirement\s+([A-Za-z0-9_.-]+)==([^\s;]+)",
        )
        match = next((re.search(pattern, diagnostic, re.IGNORECASE) for pattern in patterns
                      if re.search(pattern, diagnostic, re.IGNORECASE)), None)
        if not match:
            return None
        name, version = match.group(1), match.group(2).rstrip("',\"`)")
        evidence = probe_pypi_release(name, version, python_version)
        evidence["package"] = name
        evidence["version"] = version
        return evidence

    @staticmethod
    def _classify_resolver_failure(diagnostic: str) -> tuple[str, str]:
        value = diagnostic.casefold()
        if "resolutionimpossible" in value or "conflicting dependencies" in value:
            return "incompatible", "dependency_conflict"
        if any(marker in value for marker in (
            "requires-python", "requires a different python", "not supported on this python",
        )):
            return "incompatible", "python_incompatible"
        if any(marker in value for marker in (
            "could not fetch url", "temporary failure", "name resolution",
            "connectionerror", "connection refused", "connection timed out",
            "read timed out", "proxyerror", "sslerror", "max retries exceeded",
        )):
            return "unknown", "network_error"
        if any(marker in value for marker in (
            "401 client error", "403 client error", "404 client error",
            "unauthorized", "forbidden", "invalid index url",
        )):
            return "unknown", "index_error"
        if "no matching distribution found" in value or "could not find a version" in value:
            return "unknown", "no_compatible_binary_or_index_release"
        return "unknown", "resolver_error"

    @staticmethod
    def _set_status(
        plan: FixPlan,
        status: str,
        resolution: str,
        detail: str | None = None,
    ) -> None:
        plan.dependency_resolution = resolution
        plan.dependency_resolution_status = detail or resolution
        for recommendation in plan.recommendations:
            if recommendation.suggested_version:
                recommendation.compatibility_status = status
