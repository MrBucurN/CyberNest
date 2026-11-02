import re
from dataclasses import asdict, dataclass, field

from packaging.utils import canonicalize_name


_ADVISORY_ID = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|PYSEC-\d{4}-\d+|GHSA-[A-Za-z0-9-]+)\b",
    re.IGNORECASE,
)
_VALID_SCAN_STATUSES = {"success", "failed", "skipped"}


@dataclass
class FixVerification:
    status: str
    scope_status: str
    previous_findings: int
    current_findings: int
    resolved: list[dict] = field(default_factory=list)
    remaining: list[dict] = field(default_factory=list)
    new: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    scope_details: dict[str, object] = field(default_factory=dict)
    scoped_verification: dict[str, object] | None = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["overall_status"] = self.status
        return data


def compare_reports(previous: dict, current: dict) -> FixVerification:
    """Compare reports without treating missing coverage as a fix."""
    warnings: list[str] = []
    validation_warnings = _validate_reports(previous, current)
    if validation_warnings:
        return FixVerification(
            status="inconclusive",
            scope_status="unknown",
            previous_findings=0,
            current_findings=0,
            warnings=validation_warnings,
            scope_details={"comparison": "invalid_report"},
        )

    old_findings = _findings(previous)
    new_findings = _findings(current)
    old_target = previous.get("target")
    new_target = current.get("target")
    if not old_target or not new_target:
        scope_status = "unknown"
        warnings.append("One or both reports do not record the scan target.")
    elif str(old_target).casefold() != str(new_target).casefold():
        scope_status = "mismatch"
        warnings.append("Reports were generated for different target paths.")
    else:
        scope_status = "matched"

    old_scanners = _scanner_statuses(previous)
    new_scanners = _scanner_statuses(current)
    if not old_scanners or not new_scanners or old_scanners != new_scanners:
        scope_status = "mismatch"
        warnings.append("The set of scanners differs between reports.")
    if any(
        status != "success"
        for status in (*old_scanners.values(), *new_scanners.values())
    ):
        scope_status = "mismatch"
        warnings.append(
            "At least one scanner failed or was skipped; absence of findings is inconclusive."
        )

    scope_details, scope_warnings = _compare_scope(previous, current)
    warnings.extend(scope_warnings)
    if scope_details.get("status") == "mismatch":
        scope_status = "mismatch"
    elif scope_details.get("status") == "unknown":
        if scope_status == "matched":
            scope_status = "unknown"
        warnings.append(
            "Scope metadata is missing or incomplete; older reports cannot be treated as full verification."
        )

    public_old = [_public_finding(item) for item in old_findings]
    if scope_status != "matched":
        scoped = _compare_direct_dependency_scope(previous, current)
        warnings.extend(scoped.get("warnings", []))
        return FixVerification(
            status="inconclusive",
            scope_status=scope_status,
            previous_findings=len(old_findings),
            current_findings=len(new_findings),
            remaining=public_old,
            warnings=_unique(warnings),
            scope_details=scope_details,
            scoped_verification=scoped,
        )

    unmatched = list(new_findings)
    resolved, remaining = [], []
    for old in old_findings:
        match_index = next(
            (
                index
                for index, new in enumerate(unmatched)
                if _same_finding(old, new)
            ),
            None,
        )
        if match_index is None:
            resolved.append(_public_finding(old))
        else:
            remaining.append({
                "previous": _public_finding(old),
                "current": _public_finding(unmatched.pop(match_index)),
            })

    new = [_public_finding(item) for item in unmatched]
    if old_findings and not remaining and not new:
        status = "resolved"
    elif not resolved and remaining and not new:
        # Retain this v1.0 aggregate name; callers should use `remaining` for
        # the finding-level state.
        status = "unresolved"
    elif not resolved and remaining and new:
        status = "unresolved_with_new_findings"
    elif resolved and not remaining and new:
        status = "resolved_with_new_findings"
    elif not old_findings and not new_findings:
        status = "no_findings"
    elif not old_findings and new:
        status = "new_findings"
    else:
        status = "partially_resolved"
    return FixVerification(
        status=status,
        scope_status=scope_status,
        previous_findings=len(old_findings),
        current_findings=len(new_findings),
        resolved=resolved,
        remaining=remaining,
        new=new,
        warnings=_unique(warnings),
        scope_details=scope_details,
    )


def _validate_reports(*reports: dict) -> list[str]:
    warnings = []
    for label, report in zip(("Previous", "Current"), reports):
        if not isinstance(report, dict):
            warnings.append(f"{label} report must be a JSON object.")
            continue
        scans = report.get("scans")
        if not isinstance(scans, list):
            warnings.append(f"{label} report does not contain a valid scans list.")
            continue
        seen = set()
        for scan in scans:
            if not isinstance(scan, dict):
                warnings.append(f"{label} report contains an invalid scanner record.")
                continue
            scanner = scan.get("scanner")
            status = scan.get("status")
            if not isinstance(scanner, str) or not scanner:
                warnings.append(f"{label} report contains a scanner without a name.")
            elif scanner in seen:
                warnings.append(f"{label} report lists scanner {scanner!r} more than once.")
            seen.add(scanner)
            if status not in _VALID_SCAN_STATUSES:
                warnings.append(f"{label} report contains an invalid scanner status.")
            if status == "success" and not isinstance(scan.get("findings"), list):
                warnings.append(
                    f"{label} report has no valid findings list for successful scanner {scanner!r}."
                )
            findings = scan.get("findings", [])
            if isinstance(findings, list) and any(not isinstance(item, dict) for item in findings):
                warnings.append(f"{label} report contains an invalid finding record.")
    return _unique(warnings)


def _compare_scope(previous: dict, current: dict) -> tuple[dict[str, object], list[str]]:
    old_scope = previous.get("scan_scope")
    new_scope = current.get("scan_scope")
    if not isinstance(old_scope, dict) or not isinstance(new_scope, dict):
        return {"status": "unknown", "metadata": "legacy_or_missing"}, []

    modern_reports = all("scan_scope" in report for report in (previous, current))
    if modern_reports and (
        old_scope.get("coverage_status") != "complete"
        or new_scope.get("coverage_status") != "complete"
    ):
        return {
            "status": "mismatch",
            "previous_coverage_status": old_scope.get("coverage_status", "unknown"),
            "current_coverage_status": new_scope.get("coverage_status", "unknown"),
        }, [
            "One or both modern reports do not contain complete scan coverage; verification is inconclusive."
        ]

    old_files = _sorted_strings(old_scope.get("dependency_files"))
    new_files = _sorted_strings(new_scope.get("dependency_files"))
    old_ecosystems = _sorted_strings(old_scope.get("ecosystems"))
    new_ecosystems = _sorted_strings(new_scope.get("ecosystems"))
    if old_files != new_files or old_ecosystems != new_ecosystems:
        return {
            "status": "mismatch",
            "previous_dependency_files": old_files,
            "current_dependency_files": new_files,
            "previous_ecosystems": old_ecosystems,
            "current_ecosystems": new_ecosystems,
        }, ["Dependency files or package ecosystems differ between reports."]

    old_scopes = _scope_by_scanner(old_scope)
    new_scopes = _scope_by_scanner(new_scope)
    if old_scopes != new_scopes:
        return {
            "status": "mismatch",
            "previous_scanners": old_scopes,
            "current_scanners": new_scopes,
        }, ["Scanner coverage metadata differs between reports."]

    return {
        "status": "matched",
        "dependency_files": new_files,
        "ecosystems": new_ecosystems,
    }, []


def _compare_direct_dependency_scope(previous: dict, current: dict) -> dict[str, object]:
    """Compare only an identical, fully scanned direct dependency inventory."""
    def inconclusive(reason: str) -> dict[str, object]:
        return {
            "status": "inconclusive",
            "scope": "direct_dependencies",
            "previous_findings": 0,
            "current_findings": 0,
            "resolved": [],
            "remaining": [],
            "new": [],
            "warnings": [reason],
        }

    if str(previous.get("target", "")).casefold() != str(current.get("target", "")).casefold():
        return inconclusive("Scoped verification requires the same recorded project target.")
    old_statuses, new_statuses = _scanner_statuses(previous), _scanner_statuses(current)
    if not old_statuses or old_statuses != new_statuses or any(
        status != "success" for status in (*old_statuses.values(), *new_statuses.values())
    ):
        return inconclusive("Scoped verification requires the same successful scanner set.")

    old_scope, new_scope = previous.get("scan_scope"), current.get("scan_scope")
    if not isinstance(old_scope, dict) or not isinstance(new_scope, dict):
        return inconclusive("Legacy reports do not contain enough scope metadata for scoped verification.")
    old_files, new_files = _sorted_strings(old_scope.get("dependency_files")), _sorted_strings(new_scope.get("dependency_files"))
    old_ecosystems, new_ecosystems = _sorted_strings(old_scope.get("ecosystems")), _sorted_strings(new_scope.get("ecosystems"))
    if not old_files or old_files != new_files or old_ecosystems != new_ecosystems:
        return inconclusive("Dependency manifests or ecosystems changed between reports.")

    old_keys = _direct_dependency_keys(previous)
    new_keys = _direct_dependency_keys(current)
    if old_keys is None or new_keys is None:
        return inconclusive("A direct dependency inventory was missing, incomplete, or not independently verifiable.")
    if old_keys != new_keys:
        return inconclusive("The verified direct dependency set changed; removed or added packages are not counted as resolved.")
    if not old_keys:
        return inconclusive("No non-empty direct dependency set was available for scoped verification.")

    old_findings = _direct_findings(previous, old_keys)
    new_findings = _direct_findings(current, new_keys)
    unmatched = list(new_findings)
    resolved, remaining = [], []
    for old in old_findings:
        match_index = next((
            index for index, new in enumerate(unmatched) if _same_finding(old, new)
        ), None)
        if match_index is None:
            resolved.append(_public_finding(old))
        else:
            remaining.append({
                "previous": _public_finding(old),
                "current": _public_finding(unmatched.pop(match_index)),
            })
    new = [_public_finding(item) for item in unmatched]
    status = _verification_status(old_findings, remaining, resolved, new, new_findings)
    return {
        "status": status,
        "scope": "direct_dependencies",
        "scope_status": "matched",
        "dependency_files": old_files,
        "ecosystems": old_ecosystems,
        "previous_findings": len(old_findings),
        "current_findings": len(new_findings),
        "resolved": resolved,
        "remaining": remaining,
        "new": new,
        "warnings": [
            "Scoped results cover only the identical, verified direct dependencies; overall project coverage remains incomplete."
        ],
    }


def _direct_dependency_keys(report: dict) -> set[tuple[str, str, str]] | None:
    scope = report.get("scan_scope")
    if not isinstance(scope, dict) or scope.get("coverage_status") not in {"complete", "incomplete"}:
        return None
    scanner_records = scope.get("scanners")
    scans = report.get("scans")
    if not isinstance(scanner_records, list) or not isinstance(scans, list):
        return None
    scan_by_name = {
        item.get("scanner"): item for item in scans
        if isinstance(item, dict) and isinstance(item.get("scanner"), str)
    }
    keys: set[tuple[str, str, str]] = set()
    seen_scanners = set()
    for scanner_record in scanner_records:
        if not isinstance(scanner_record, dict):
            return None
        scanner = scanner_record.get("scanner")
        scan = scan_by_name.get(scanner)
        if not isinstance(scanner, str) or scanner in seen_scanners or not isinstance(scan, dict):
            return None
        seen_scanners.add(scanner)
        if scan.get("status") != "success" or scanner_record.get("status") != "success":
            return None
        if scanner_record.get("inventory_available") is not True:
            return None
        coverage = scanner_record.get("dependency_coverage")
        if not isinstance(coverage, dict):
            scan_scope = scan.get("scope")
            coverage = scan_scope.get("dependency_coverage") if isinstance(scan_scope, dict) else None
        if not isinstance(coverage, dict) or coverage.get("target_context_status") != "runtime_context":
            return None
        if coverage.get("unsupported_files"):
            return None
        manifests = coverage.get("manifests")
        dependencies = scan.get("dependencies")
        if not isinstance(manifests, list) or not isinstance(dependencies, list):
            return None
        for manifest in manifests:
            if not isinstance(manifest, dict):
                return None
            label = manifest.get("manifest")
            declared = manifest.get("direct_dependencies_declared")
            scanned = manifest.get("direct_dependencies_scanned")
            not_applicable = manifest.get("direct_dependencies_not_applicable", 0)
            unscanned = manifest.get("direct_dependencies_unscanned", [])
            if (
                not isinstance(label, str) or not label
                or manifest.get("direct_coverage_status") != "complete"
                or isinstance(declared, bool) or not isinstance(declared, int)
                or isinstance(scanned, bool) or not isinstance(scanned, int)
                or not_applicable != 0 or unscanned
                or declared != scanned
            ):
                return None
            names = set()
            for dependency in dependencies:
                if not isinstance(dependency, dict) or dependency.get("source_file") != label:
                    continue
                if dependency.get("direct") is not True or not isinstance(dependency.get("name"), str):
                    continue
                names.add(canonicalize_name(dependency["name"]))
            if len(names) != scanned:
                return None
            keys.update((scanner, label, name) for name in names)
    return keys if seen_scanners == set(scan_by_name) else None


def _direct_findings(report: dict, direct_keys: set[tuple[str, str, str]]) -> list[dict]:
    scoped = []
    for scan in report.get("scans", []):
        if not isinstance(scan, dict) or scan.get("status") != "success":
            continue
        scanner = scan.get("scanner", "")
        for finding in scan.get("findings", []):
            if not isinstance(finding, dict) or finding.get("dependency_direct") is not True:
                continue
            source = finding.get("dependency_source")
            package = finding.get("affected_component")
            if not isinstance(source, str) or not isinstance(package, str):
                continue
            if (scanner, source, canonicalize_name(package)) in direct_keys:
                record = dict(finding)
                record["_scanner"] = scanner
                scoped.append(record)
    return _canonicalize_alias_findings(scoped)


def _verification_status(old_findings, remaining, resolved, new, new_findings) -> str:
    if old_findings and not remaining and not new:
        return "resolved"
    if not resolved and remaining and not new:
        return "unresolved"
    if not resolved and remaining and new:
        return "unresolved_with_new_findings"
    if resolved and not remaining and new:
        return "resolved_with_new_findings"
    if not old_findings and not new_findings:
        return "no_findings"
    if not old_findings and new:
        return "new_findings"
    return "partially_resolved"


def _scope_by_scanner(scope: dict) -> dict[str, dict[str, object]]:
    values = scope.get("scanners")
    if not isinstance(values, list):
        return {}
    result = {}
    for item in values:
        if not isinstance(item, dict) or not isinstance(item.get("scanner"), str):
            continue
        result[item["scanner"]] = {
            "status": item.get("status", "unknown"),
            "coverage_status": item.get("coverage_status", "unknown"),
            "dependency_files": _sorted_strings(item.get("dependency_files")),
            "ecosystems": _sorted_strings(item.get("ecosystems")),
            "inventory_available": bool(item.get("inventory_available", False)),
        }
    return result


def _scanner_statuses(report: dict) -> dict[str, str]:
    scans = report.get("scans")
    if not isinstance(scans, list):
        return {}
    return {
        scan.get("scanner", ""): scan.get("status", "unknown")
        for scan in scans
        if isinstance(scan, dict) and isinstance(scan.get("scanner"), str)
    }


def _findings(report: dict) -> list[dict]:
    findings = []
    for scan in report.get("scans", []):
        if not isinstance(scan, dict) or scan.get("status") != "success":
            continue
        scanner = scan.get("scanner", "")
        for finding in scan.get("findings", []):
            if isinstance(finding, dict):
                record = dict(finding)
                record["_scanner"] = scanner
                findings.append(record)
    return _canonicalize_alias_findings(findings)


def _canonicalize_alias_findings(findings: list[dict]) -> list[dict]:
    """Collapse duplicate records for the same package/advisory alias group."""
    result: list[dict] = []
    for finding in findings:
        ids = _ids(finding)
        package = canonicalize_name(str(finding.get("affected_component", "")))
        matches = []
        if ids:
            for existing in result:
                same_context = (
                    existing.get("_scanner") == finding.get("_scanner")
                    and canonicalize_name(str(existing.get("affected_component", ""))) == package
                    and existing.get("ecosystem") == finding.get("ecosystem")
                )
                if same_context and ids & _ids(existing):
                    matches.append(existing)
        if not matches:
            copied = dict(finding)
            copied["advisory_ids"] = sorted(ids) if ids else list(finding.get("advisory_ids", []))
            if ids:
                copied["canonical_id"] = min(ids, key=_canonical_id_priority)
            result.append(copied)
            continue

        primary = matches[0]
        merged_ids = set(ids)
        for existing in matches:
            merged_ids.update(_ids(existing))
        primary["advisory_ids"] = sorted(merged_ids)
        primary["canonical_id"] = min(merged_ids, key=_canonical_id_priority)
        for existing in matches[1:]:
            result.remove(existing)
        # Include identifiers that became connected after the merge.
        changed = True
        while changed:
            changed = False
            for existing in list(result):
                if existing is primary:
                    continue
                same_context = (
                    existing.get("_scanner") == primary.get("_scanner")
                    and canonicalize_name(str(existing.get("affected_component", ""))) == package
                    and existing.get("ecosystem") == primary.get("ecosystem")
                )
                if same_context and merged_ids & _ids(existing):
                    merged_ids.update(_ids(existing))
                    result.remove(existing)
                    changed = True
        primary["advisory_ids"] = sorted(merged_ids)
        primary["canonical_id"] = min(merged_ids, key=_canonical_id_priority)
    return result


def _canonical_id_priority(value: str) -> tuple[int, str]:
    if value.startswith("CVE-"):
        return 0, value
    if value.startswith("GHSA-"):
        return 1, value
    if value.startswith("PYSEC-"):
        return 2, value
    return 3, value


def _ids(finding: dict) -> set[str]:
    values = finding.get("advisory_ids", [])
    values = list(values) if isinstance(values, list) else []
    values.extend([
        str(finding.get("title", "")),
        str(finding.get("evidence", "")),
        str(finding.get("advisory_url", "")),
    ])
    return {
        value.upper()
        for text in values
        for value in _ADVISORY_ID.findall(str(text))
    }


def _same_finding(previous: dict, current: dict) -> bool:
    if previous.get("_scanner") != current.get("_scanner"):
        return False
    if canonicalize_name(str(previous.get("affected_component", ""))) != canonicalize_name(
        str(current.get("affected_component", ""))
    ):
        return False
    old_ecosystem = previous.get("ecosystem")
    new_ecosystem = current.get("ecosystem")
    if old_ecosystem and new_ecosystem and old_ecosystem != new_ecosystem:
        return False
    old_ids, new_ids = _ids(previous), _ids(current)
    if old_ids and new_ids:
        return bool(old_ids & new_ids)
    return previous.get("title") == current.get("title")


def _public_finding(finding: dict) -> dict:
    return {key: value for key, value in finding.items() if key != "_scanner"}


def _sorted_strings(value) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({item for item in value if isinstance(item, str)})


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))
