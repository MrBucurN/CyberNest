
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from packaging.version import InvalidVersion, Version
from packaging.utils import canonicalize_name
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.markers import InvalidMarker, Marker

from cybernest.deduplication import deduplicate_findings
from cybernest.finding import Finding
from cybernest.integrations.advisory_severity import AdvisorySeverityResolver
from cybernest.integrations.base import BaseScanner
from cybernest.fixes.index_probe import probe_pypi_release
from cybernest.project_discovery import ProjectDiscovery, discover_project
from cybernest.scan_result import ScanResult, ScanStatus


class PipAuditScanner(BaseScanner):
    name = "pip-audit"

    @staticmethod
    def _scope(
        *,
        status: ScanStatus,
        inventory_available: bool,
        discovery: ProjectDiscovery | None = None,
        coverage_status: str | None = None,
        dependency_coverage: dict[str, object] | None = None,
    ) -> dict[str, object]:
        dependency_files = []
        unsupported_files = []
        warnings = []
        if discovery is not None:
            dependency_files = [manifest.label for manifest in discovery.manifests]
            unsupported_files = list(dict.fromkeys(discovery.unsupported_files))
            warnings = list(dict.fromkeys(discovery.warnings))
        runtime_python = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        if discovery and discovery.python_target_confidence == "range" and not discovery.python_target:
            target_python = "unknown"
        else:
            target_python = discovery.python_target if discovery and discovery.python_target else runtime_python
        if discovery and discovery.python_target_confidence == "range":
            target_source, target_confidence = discovery.python_target_source, "range"
        elif discovery and discovery.python_target:
            target_source, target_confidence = discovery.python_target_source, discovery.python_target_confidence
        else:
            target_source, target_confidence = "runtime interpreter", "assumed"
        return {
            "scanner": "pip-audit",
            "status": status.value,
            "scanner_execution_status": status.value,
            "coverage_status": coverage_status or (
                "complete" if status == ScanStatus.SUCCESS else "incomplete"
            ),
            "security_scan_coverage": coverage_status or (
                "complete" if status == ScanStatus.SUCCESS else "incomplete"
            ),
            "dependency_coverage": dependency_coverage or {
                "direct_dependencies": {
                    "declared_count": 0,
                    "scanned_count": 0,
                    "not_applicable_count": 0,
                    "unscanned_count": 0,
                    "status": "unknown",
                },
                "transitive_dependencies": {
                    "scanned_count": 0,
                    "status": "unknown",
                },
                "manifests": [],
                "scanned_dependency_count": 0,
            },
            "dependency_files": dependency_files,
            "unsupported_files": unsupported_files,
            "warnings": warnings,
            "supported_formats": sorted({manifest.format for manifest in discovery.manifests}) if discovery else [],
            "ecosystems": ["pypi"],
            "inventory_available": inventory_available,
            "python_target": target_python,
            "python_target_source": target_source,
            "python_target_confidence": target_confidence,
            "python_target_conflict": bool(discovery and discovery.python_target_conflict),
            "python_requires": discovery.requires_python if discovery else "",
            "resolver_python_version": runtime_python,
            "python_scan_status": (
                "cross_target_unverified"
                if target_python != "unknown" and not _same_python_target(target_python, runtime_python)
                else "range_resolved_under_runtime"
                if target_confidence == "range"
                else "runtime_context"
            ),
        }

    def __init__(self, python_target_override: str | None = None):
        self.severity_resolver = AdvisorySeverityResolver()
        self.dependencies: list[dict[str, object]] = []
        self.discovery: ProjectDiscovery | None = None
        self._successful_manifest_count = 0
        self.python_target_override = python_target_override
        self.manifest_coverage: list[dict[str, object]] = []

    def scan(self, target: Path) -> list[Finding]:
        """Scan supported dependency manifests and merge their findings."""
        self.dependencies = []
        if not target.is_dir():
            raise NotADirectoryError(
                f"Target folder not found: {target}"
            )
        discovery = discover_project(target)
        self.discovery = discovery
        self.manifest_coverage = self._initial_manifest_coverage(discovery)
        self._apply_scan_python_context(discovery)
        findings, failed = self._scan_manifests(target, discovery)
        if failed and self._successful_manifest_count == 0:
            raise RuntimeError("; ".join(failed))
        if not discovery.manifests:
            return []
        return findings

    def _scan_manifests(
        self, target: Path, discovery: ProjectDiscovery
    ) -> tuple[list[Finding], list[str]]:
        findings: list[Finding] = []
        failed: list[str] = []
        self._successful_manifest_count = 0
        with tempfile.TemporaryDirectory(prefix="cybernest-scan-") as directory:
            temp_root = Path(directory)
            for index, manifest in enumerate(discovery.manifests):
                coverage = self.manifest_coverage[index]
                if manifest.unsupported_reason:
                    coverage["status"] = "unsupported"
                    coverage["reason"] = manifest.unsupported_reason
                    coverage["transitive_coverage_status"] = "incomplete"
                    continue
                if not manifest.direct_dependencies:
                    self._successful_manifest_count += 1
                    coverage["status"] = "complete"
                    coverage["direct_coverage_status"] = "complete"
                    coverage["transitive_coverage_status"] = "not_applicable"
                    continue
                requirement_path = manifest.path
                if manifest.format != "requirements":
                    requirement_path = temp_root / f"requirements-{index}.txt"
                    requirement_path.write_text(
                        "\n".join(manifest.requirements) + ("\n" if manifest.requirements else ""),
                        encoding="utf-8",
                    )
                try:
                    environment = os.environ.copy()
                    environment["PIP_ONLY_BINARY"] = ":all:"
                    command = [
                        sys.executable, "-m", "pip_audit",
                        "--requirement", str(requirement_path),
                        "--format", "json",
                    ]
                    result = subprocess.run(
                        command, cwd=target, capture_output=True, text=True,
                        timeout=120, check=False, env=environment,
                    )
                    data = None
                    resolution_diagnostic = ""
                    resolver_mode = "full"
                    if result.returncode not in (0, 1):
                        resolution_diagnostic = self._sanitize_diagnostic(
                            result.stderr.strip() or "pip-audit dependency resolution failed."
                        )
                    else:
                        try:
                            data = json.loads(result.stdout)
                            if not isinstance(data, dict) or not isinstance(
                                data.get("dependencies"), list
                            ):
                                resolution_diagnostic = (
                                    "pip-audit did not return a JSON dependency inventory. "
                                    + self._sanitize_diagnostic(result.stderr.strip())
                                )
                        except json.JSONDecodeError:
                            resolution_diagnostic = self._sanitize_diagnostic(
                                result.stderr.strip()
                                or "pip-audit returned no valid JSON dependency inventory."
                            )
                    if resolution_diagnostic:
                        if not self._all_requirements_are_exact_pins(manifest):
                            raise RuntimeError(resolution_diagnostic)
                        failure_evidence = self._classify_resolution_failure(
                            resolution_diagnostic,
                            discovery.python_target or (
                                f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
                            ),
                        )
                        resolver_mode = "direct_only"
                        direct_command = [
                            *command[:-2], "--no-deps", "--disable-pip",
                            "--format", "json",
                        ]
                        direct_result = subprocess.run(
                            direct_command, cwd=target, capture_output=True,
                            text=True, timeout=60, check=False, env=environment,
                        )
                        if direct_result.returncode not in (0, 1):
                            raise RuntimeError(self._sanitize_diagnostic(
                                direct_result.stderr.strip() or "Direct-only pip-audit failed."
                            ))
                        result = direct_result
                        data = json.loads(result.stdout)
                        if not isinstance(data, dict) or not isinstance(
                            data.get("dependencies"), list
                        ):
                            raise RuntimeError(
                                "Direct-only pip-audit did not return a JSON dependency inventory."
                            )
                        discovery.warnings.append(
                            f"{manifest.label}: {failure_evidence['reason']}"
                        )
                    resolved_names = {
                        canonicalize_name(item["name"])
                        for item in data.get("dependencies", [])
                        if isinstance(item, dict) and isinstance(item.get("name"), str)
                    }
                    declared_by_name: dict[str, list[dict[str, str | bool]]] = {}
                    for dependency in manifest.direct_dependencies:
                        declared_by_name.setdefault(
                            str(dependency.get("canonical_name", "")), []
                        ).append(dependency)
                    direct_names = set(declared_by_name) - {""}
                    scanned_direct = direct_names & resolved_names
                    not_applicable = {
                        package for package in direct_names - resolved_names
                        if self._marker_excludes_all(declared_by_name[package])
                    }
                    unscanned_direct = sorted(
                        direct_names - scanned_direct - not_applicable
                    )
                    transitive_names = resolved_names - direct_names
                    coverage["resolver_mode"] = resolver_mode
                    coverage["dependencies_scanned"] = len(resolved_names)
                    coverage["direct_dependencies_scanned"] = len(scanned_direct)
                    coverage["direct_dependencies_not_applicable"] = len(not_applicable)
                    coverage["direct_dependencies_unscanned"] = unscanned_direct
                    coverage["transitive_dependencies_scanned"] = len(transitive_names)
                    coverage["direct_coverage_status"] = (
                        "incomplete" if unscanned_direct else "complete"
                    )
                    coverage["transitive_coverage_status"] = (
                        "incomplete" if resolver_mode == "direct_only"
                        else "complete" if transitive_names
                        else "not_applicable"
                    )
                    if resolver_mode == "direct_only":
                        coverage["status"] = "partial"
                        coverage["reason"] = failure_evidence["reason"]
                        coverage["resolution_failure"] = {
                            key: value for key, value in failure_evidence.items()
                            if key != "reason"
                        }
                    elif unscanned_direct:
                        coverage["status"] = "partial"
                        coverage["reason"] = "Some declared direct dependencies were absent from the resolved inventory."
                        discovery.warnings.append(
                            f"{manifest.label}: {len(unscanned_direct)} declared direct dependencies were not present in the pip-audit inventory."
                        )
                    else:
                        coverage["status"] = "complete"
                    findings.extend(self._map_result(data, manifest, target))
                    self._successful_manifest_count += 1
                except (OSError, subprocess.TimeoutExpired, RuntimeError, ValueError, json.JSONDecodeError) as error:
                    failed.append(f"{manifest.label}: {error}")
                    coverage["status"] = "failed"
                    coverage["reason"] = self._sanitize_diagnostic(str(error))
                    coverage["transitive_coverage_status"] = "incomplete"
        return deduplicate_findings(findings), failed

    @staticmethod
    def _initial_manifest_coverage(
        discovery: ProjectDiscovery,
    ) -> list[dict[str, object]]:
        return [{
            "manifest": manifest.label,
            "format": manifest.format,
            "status": "unsupported" if manifest.unsupported_reason else "pending",
            "direct_dependencies_declared": len(manifest.direct_dependencies),
            "direct_dependencies_scanned": 0,
            "direct_dependencies_not_applicable": 0,
            "direct_dependencies_unscanned": [],
            "transitive_dependencies_scanned": 0,
            "dependencies_scanned": 0,
            "resolver_mode": "not_run",
            "direct_coverage_status": "unknown",
            "transitive_coverage_status": "unknown",
            "reason": manifest.unsupported_reason,
        } for manifest in discovery.manifests]

    @staticmethod
    def _marker_excludes_all(dependencies: list[dict[str, str | bool]]) -> bool:
        markers = [str(item.get("marker", "")) for item in dependencies]
        if not markers or any(not marker for marker in markers):
            return False
        try:
            return all(not Marker(marker).evaluate() for marker in markers)
        except InvalidMarker:
            return False

    def _dependency_coverage(self) -> dict[str, object]:
        manifests = list(self.manifest_coverage)
        discovery = self.discovery
        target_context = "runtime_context"
        if discovery and discovery.python_target_conflict:
            target_context = "target_conflict"
        elif discovery and discovery.python_target_confidence == "range":
            target_context = "range_resolved_under_runtime"
        elif discovery and discovery.python_target:
            runtime = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            if not _same_python_target(discovery.python_target, runtime):
                target_context = "cross_target_unverified"
        direct_declared = sum(int(item.get("direct_dependencies_declared", 0)) for item in manifests)
        direct_scanned = sum(int(item.get("direct_dependencies_scanned", 0)) for item in manifests)
        direct_not_applicable = sum(
            int(item.get("direct_dependencies_not_applicable", 0)) for item in manifests
        )
        unscanned = [
            {"manifest": item.get("manifest", ""), "package": package}
            for item in manifests
            for package in item.get("direct_dependencies_unscanned", [])
        ]
        incomplete_manifests = [
            item for item in manifests if item.get("status") in {"partial", "failed", "unsupported", "pending"}
        ]
        transitive_scanned = sum(
            int(item.get("transitive_dependencies_scanned", 0)) for item in manifests
        )
        transitive_status = (
            "unknown" if not manifests
            else "incomplete" if incomplete_manifests or target_context != "runtime_context"
            else "complete" if transitive_scanned
            else "not_applicable"
        )
        return {
            "direct_dependencies": {
                "declared_count": direct_declared,
                "scanned_count": direct_scanned,
                "not_applicable_count": direct_not_applicable,
                "unscanned_count": len(unscanned),
                "unscanned": unscanned,
                "status": (
                    "incomplete"
                    if unscanned or incomplete_manifests or target_context != "runtime_context"
                    else "complete"
                ),
            },
            "transitive_dependencies": {
                "scanned_count": transitive_scanned,
                "status": transitive_status,
                "reason": (
                    "At least one manifest was not fully resolved."
                    if incomplete_manifests
                    else "Resolution was performed under a different or non-specific Python target."
                    if target_context != "runtime_context"
                    else ""
                ),
            },
            "target_context_status": target_context,
            "manifests": manifests,
            "scanned_dependency_count": sum(
                int(item.get("dependencies_scanned", 0)) for item in manifests
            ),
            "unsupported_files": list(dict.fromkeys(
                self.discovery.unsupported_files if self.discovery else []
            )),
        }

    @staticmethod
    def _all_requirements_are_exact_pins(manifest: DependencyManifest) -> bool:
        if not manifest.direct_dependencies:
            return False
        from packaging.specifiers import InvalidSpecifier, SpecifierSet

        for dependency in manifest.direct_dependencies:
            specifier = str(dependency.get("specifier", ""))
            marker = str(dependency.get("marker", ""))
            try:
                specifiers = list(SpecifierSet(specifier))
            except InvalidSpecifier:
                return False
            if (
                len(specifiers) != 1
                or specifiers[0].operator != "=="
                or "*" in specifiers[0].version
                or marker
            ):
                return False
        return True

    @staticmethod
    def _classify_resolution_failure(
        diagnostic: str, python_version: str
    ) -> dict[str, object]:
        """Explain why full resolution stopped without executing source builds."""
        text = PipAuditScanner._sanitize_diagnostic(diagnostic)
        lowered = text.casefold()
        base: dict[str, object] = {"python_target": python_version}

        if any(marker in lowered for marker in (
            "429", "too many requests", "rate limit", "rate-limited",
        )):
            base["classification"] = "rate_limited"
            base["reason"] = (
                "Only exact-pinned direct dependencies were scanned; the package index "
                "rate-limited transitive dependency resolution."
            )
            return base
        if any(marker in lowered for marker in (
            "could not fetch url", "could not resolve", "temporary failure", "name resolution",
            "connectionerror", "connection refused", "connection timed out",
            "read timed out", "proxyerror", "sslerror", "max retries exceeded",
        )):
            base["classification"] = "network_error"
            base["reason"] = (
                "Only exact-pinned direct dependencies were scanned; the package index "
                "could not be reached to resolve transitive dependencies."
            )
            return base
        if any(marker in lowered for marker in (
            "401 client error", "403 client error", "unauthorized", "forbidden",
            "invalid index url",
        )):
            base["classification"] = "index_error"
            base["reason"] = (
                "Only exact-pinned direct dependencies were scanned; the package index "
                "denied access or returned a service error during transitive resolution."
            )
            return base
        if "requires-python" in lowered or "requires a different python" in lowered:
            base["classification"] = "python_incompatible"
            base["reason"] = (
                "Only exact-pinned direct dependencies were scanned; a transitive package "
                f"is incompatible with Python {python_version}."
            )
            return base
        if "resolutionimpossible" in lowered or "conflicting dependencies" in lowered:
            base["classification"] = "dependency_conflict"
            base["reason"] = (
                "Only exact-pinned direct dependencies were scanned; pip reported a "
                "transitive dependency conflict."
            )
            return base

        match = re.search(
            r"(?:No matching distribution found for|requirement)\s+"
            r"([A-Za-z0-9_.-]+)==([^\s;]+)", text, re.IGNORECASE,
        )
        if match and ("no matching distribution" in lowered or "could not find a version" in lowered):
            package, version = match.group(1), match.group(2).rstrip("',\"`)")
            base.update({"package": package, "version": version})
            metadata = probe_pypi_release(package, version, python_version)
            metadata_status = metadata.get("status", "unknown") if isinstance(metadata, dict) else "unknown"
            base["metadata_lookup_status"] = metadata_status
            if isinstance(metadata, dict) and metadata_status == "available":
                base["pypi_release_exists"] = metadata.get("release_exists")
                base["target_wheel_available"] = metadata.get("target_wheel_available")
                base["source_archive_available"] = metadata.get("source_archive_available")
                if metadata.get("python_compatible") is False:
                    base["classification"] = "python_incompatible"
                    base["reason"] = (
                        f"Only exact-pinned direct dependencies were scanned; {package}=={version} "
                        f"does not support Python {python_version}."
                    )
                elif metadata.get("target_wheel_available") is False:
                    source_note = (
                        " A source archive exists, but source builds are disabled and were not tested."
                        if metadata.get("source_archive_available")
                        else " No source archive was listed for this release."
                    )
                    base["classification"] = "no_compatible_wheel"
                    base["reason"] = (
                        "Only exact-pinned direct dependencies were scanned; no compatible "
                        f"binary wheel was found for {package}=={version} on Python {python_version}."
                        f"{source_note}"
                    )
                else:
                    base["classification"] = "binary_resolution_failed"
                    base["reason"] = (
                        "Only exact-pinned direct dependencies were scanned; pip could not "
                        f"resolve {package}=={version} despite PyPI release metadata being available."
                    )
            else:
                base["classification"] = "distribution_status_unknown"
                base["reason"] = (
                    "Only exact-pinned direct dependencies were scanned; pip could not find "
                    f"a matching binary distribution for {package}=={version}. PyPI metadata "
                    f"could not confirm wheel availability ({metadata_status}); compatibility remains unknown."
                )
            if isinstance(metadata, dict):
                base["metadata_source"] = metadata.get("source", "")
            return base

        base["classification"] = "resolver_error"
        base["reason"] = (
            "Only exact-pinned direct dependencies were scanned; transitive dependency "
            "resolution failed for an unclassified reason."
        )
        return base

    @staticmethod
    def _sanitize_diagnostic(value: str) -> str:
        value = re.sub(
            r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@",
            r"\1<redacted>@",
            value,
        )
        value = re.sub(r"(?i)(token|password|secret)=([^\s&]+)", r"\1=<redacted>", value)
        return value[-900:]

    def _map_result(
        self, data: object, manifest: DependencyManifest, target: Path
    ) -> list[Finding]:
        if not isinstance(data, dict) or not isinstance(data.get("dependencies"), list):
            raise RuntimeError("pip-audit JSON did not contain a valid dependencies list.")
        findings = []
        direct = {
            str(item.get("canonical_name", "")): item
            for item in manifest.direct_dependencies
            if isinstance(item, dict)
        }
        for dependency in data["dependencies"]:
            if (
                not isinstance(dependency, dict)
                or not isinstance(dependency.get("name"), str)
                or not dependency.get("name")
                or not isinstance(dependency.get("version"), str)
                or not dependency.get("version")
            ):
                raise RuntimeError("pip-audit JSON contains a dependency without a valid name or version.")
            package = canonicalize_name(dependency["name"])
            declared = direct.get(package)
            inventory_item = {
                "name": dependency["name"],
                "version": dependency["version"],
                "resolved_version": dependency["version"],
                "direct": declared is not None,
                "source_file": manifest.label,
            }
            if declared:
                inventory_item["declared_specifier"] = str(declared.get("specifier", ""))
            if inventory_item not in self.dependencies:
                self.dependencies.append(inventory_item)
            vulnerabilities = dependency.get("vulns", [])
            if not isinstance(vulnerabilities, list):
                raise RuntimeError("pip-audit JSON contains an invalid vulnerabilities list.")
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    raise RuntimeError("pip-audit JSON contains an invalid vulnerability record.")
                vulnerability_id = vulnerability.get("id", "")
                aliases = vulnerability.get("aliases", [])
                identifiers = [vulnerability_id]
                if isinstance(aliases, list):
                    identifiers.extend(aliases)
                severity = self.severity_resolver.resolve(identifiers)
                description = vulnerability.get("description", "")
                advisory_warnings = []
                if isinstance(description, str) and "disputed" in description.casefold():
                    advisory_warnings.append(
                        "The advisory is marked DISPUTED by its source; verify vendor applicability."
                    )
                applicability_status = (
                    "requires_review" if advisory_warnings else "unknown"
                )
                findings.append(Finding(
                    title=vulnerability.get("id", "Unknown vulnerability"),
                    severity=severity.severity,
                    tool=self.name,
                    category="dependency",
                    cvss_score=severity.cvss_score,
                    cvss_vector=severity.cvss_vector,
                    severity_source=severity.source,
                    severity_source_url=severity.source_url,
                    cvss_version=severity.cvss_version,
                    severity_lookup_status=severity.lookup_status,
                    severity_data_origin=severity.data_origin,
                    severity_cache_age_seconds=severity.cache_age_seconds,
                    reported_severity=severity.reported_severity,
                    severity_selection_reason=severity.selection_reason,
                    advisory_ids=[value for value in identifiers if isinstance(value, str) and value],
                    advisory_warnings=advisory_warnings,
                    description=description if isinstance(description, str) else "",
                    affected_component=dependency["name"],
                    installed_version=dependency["version"],
                    resolved_version=dependency["version"],
                    declared_specifier=str(declared.get("specifier", "")) if declared else "",
                    dependency_source=manifest.label,
                    dependency_direct=declared is not None,
                    applicability_status=applicability_status,
                    applicability_reason=(
                        "The advisory is disputed by its source; applicability needs review."
                        if advisory_warnings else "Project runtime and usage conditions were not evaluated."
                    ),
                    fixed_version=", ".join(vulnerability.get("fix_versions", [])),
                    advisory_url=vulnerability.get("link", ""),
                    evidence=(
                        f"Vulnerability ID: {vulnerability_id}"
                        + (f"; Severity source: {severity.source}" if severity.source
                           else f"; Severity: UNKNOWN; lookup status: {severity.lookup_status}")
                    ),
                    recommendation="Review the advisory and update the affected package.",
                    file_path=manifest.label,
                ))
        return findings

    def scan_with_status(self, target: Path) -> ScanResult:
        """Return the scan findings and status."""

        if not target.is_dir():
            return ScanResult(
                scanner=self.name,
                status=ScanStatus.FAILED,
                message="Target directory does not exist.",
                scope={
                    "scanner": self.name,
                    "status": ScanStatus.FAILED.value,
                    "coverage_status": "unknown",
                    "dependency_files": [],
                    "ecosystems": ["pypi"],
                    "inventory_available": False,
                },
            )

        discovery = discover_project(target)
        self.discovery = discovery
        self.manifest_coverage = self._initial_manifest_coverage(discovery)
        self._apply_scan_python_context(discovery)
        supported_manifests = [
            manifest for manifest in discovery.manifests
            if not manifest.unsupported_reason
        ]
        if not supported_manifests:
            has_any_manifest = bool(discovery.manifests or discovery.unsupported_files)
            return ScanResult(
                scanner=self.name,
                status=ScanStatus.SKIPPED,
                message=(
                    "No supported dependency manifest was found; discovered files were not scanned."
                    if has_any_manifest
                    else "No supported Python dependency manifest was found (requirements*.txt/.in, pyproject.toml, or setup.cfg)."
                ),
                scope={
                    "scanner": self.name,
                    "status": ScanStatus.SKIPPED.value,
                    "scanner_execution_status": ScanStatus.SKIPPED.value,
                    "coverage_status": "incomplete",
                    "security_scan_coverage": "incomplete",
                    "dependency_files": [manifest.label for manifest in discovery.manifests],
                    "unsupported_files": list(dict.fromkeys(discovery.unsupported_files)),
                    "warnings": list(dict.fromkeys(discovery.warnings)),
                    "supported_formats": [],
                    "ecosystems": ["pypi"],
                    "inventory_available": False,
                    "dependency_coverage": self._dependency_coverage(),
                },
            )

        try:
            self.dependencies = []
            findings, failed = self._scan_manifests(target, discovery)
            manifest_coverage_complete = all(
                item.get("status") == "complete" for item in self.manifest_coverage
            )
            scope_complete = (
                discovery.coverage_complete and not failed and manifest_coverage_complete
            )
            coverage_status = "complete" if scope_complete else "incomplete"
            if failed and self._successful_manifest_count == 0:
                raise RuntimeError("; ".join(failed))
            discovery.warnings.extend(failed)

            return ScanResult(
                scanner=self.name,
                status=ScanStatus.SUCCESS,
                findings=findings,
                message=("Scan completed successfully." if scope_complete
                         else "Scan completed with incomplete dependency coverage."),
                dependencies=list(self.dependencies),
                scope=self._scope(
                    status=ScanStatus.SUCCESS,
                    inventory_available=bool(self.dependencies) or not any(
                        manifest.direct_dependencies for manifest in supported_manifests
                    ),
                    discovery=discovery,
                    coverage_status=coverage_status,
                    dependency_coverage=self._dependency_coverage(),
                ),
            )

        except (RuntimeError, OSError, ValueError) as error:
            return ScanResult(
                scanner=self.name,
                status=ScanStatus.FAILED,
                message=str(error),
                scope=self._scope(
                    status=ScanStatus.FAILED,
                    inventory_available=False,
                    discovery=discovery,
                    coverage_status="incomplete",
                    dependency_coverage=self._dependency_coverage(),
                ),
            )

    def _apply_scan_python_context(self, discovery: ProjectDiscovery) -> None:
        runtime_python = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        target = self.python_target_override or discovery.python_target
        if self.python_target_override:
            discovery.python_target = self.python_target_override
            discovery.python_target_source = "cli"
            discovery.python_target_confidence = "explicit"
            if discovery.requires_python:
                try:
                    if not SpecifierSet(discovery.requires_python).contains(
                        Version(self.python_target_override)
                    ):
                        discovery.python_target_conflict = True
                        discovery.warnings.append(
                            f"Selected Python {self.python_target_override} is outside project requires-python {discovery.requires_python}."
                        )
                except (InvalidSpecifier, InvalidVersion):
                    discovery.python_target_conflict = True
                    discovery.warnings.append("Project requires-python metadata could not validate the CLI target.")
        elif not discovery.python_target and discovery.requires_python:
            discovery.warnings.append(
                f"Python target is a range ({discovery.requires_python}); dependency resolution uses the running Python {runtime_python}."
            )
        if target and not _same_python_target(target, runtime_python):
            discovery.warnings.append(
                f"pip-audit resolves environment markers and distributions with Python {runtime_python}; cross-target scan for Python {target} is not verified."
            )


def _same_python_target(target: str, runtime: str) -> bool:
    try:
        target_version = Version(target)
        runtime_version = Version(runtime)
    except InvalidVersion:
        return False
    return target_version.release == runtime_version.release[:len(target_version.release)]
