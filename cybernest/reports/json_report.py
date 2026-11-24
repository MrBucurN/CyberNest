import json
import os
import re
import tempfile
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
import platform
import sys

from cybernest.finding import Finding
from cybernest.scan_result import ScanResult, ScanStatus


_ADVISORY_ID = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|PYSEC-\d{4}-\d+|GHSA-[A-Za-z0-9-]+)\b",
    re.IGNORECASE,
)


def _serialize_finding(finding: Finding) -> dict:
    data = asdict(finding)
    if data["line_number"] is None:
        data.pop("line_number")
    identifiers = {
        value.upper()
        for text in [*finding.advisory_ids, finding.title]
        if isinstance(text, str)
        for value in _ADVISORY_ID.findall(text)
    }
    if identifiers:
        canonical_id = min(identifiers, key=_canonical_id_priority)
        data["canonical_id"] = canonical_id
        data["aliases"] = sorted(identifiers - {canonical_id})
    if not finding.advisory_ids:
        data.pop("advisory_ids")
    if not finding.advisory_warnings:
        data.pop("advisory_warnings")
    for field in ("resolved_version", "declared_specifier", "dependency_source", "dependency_direct"):
        if data.get(field) in ("", None):
            data.pop(field)
    if not finding.severity_lookup_status:
        for field in (
            "cvss_score",
            "cvss_vector",
            "cvss_version",
            "severity_source",
            "severity_source_url",
            "severity_lookup_status",
            "severity_data_origin",
            "severity_cache_age_seconds",
            "reported_severity",
            "severity_selection_reason",
        ):
            data.pop(field)
    return data


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


def save_report(report: dict, output_path: Path, *, overwrite: bool = False) -> None:
    """Write validated JSON atomically; only replace an existing file on request."""
    output_path = Path(output_path)
    serialized = json.dumps(report, ensure_ascii=False, indent=4, allow_nan=False)
    json.loads(serialized)
    parent = output_path.parent if str(output_path.parent) else Path(".")
    if not parent.is_dir():
        raise FileNotFoundError(f"Report directory does not exist: {parent}")

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", prefix=".cybernest-report-",
            suffix=".tmp", dir=parent, delete=False,
        ) as temporary:
            temp_path = Path(temporary.name)
            temporary.write(serialized)
            temporary.flush()
            os.fsync(temporary.fileno())
        if overwrite:
            os.replace(temp_path, output_path)
        else:
            os.link(temp_path, output_path)
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


def build_report(
    results: list[ScanResult],
    *,
    target: Path | None = None,
    fix_plan: dict | None = None,
    verification: dict | None = None,
) -> dict:
    """Build a report that can be written as JSON."""
    successful = sum(
        1 for result in results if result.status == ScanStatus.SUCCESS
    )
    skipped = sum(1 for result in results if result.status == ScanStatus.SKIPPED)
    failed = sum(1 for result in results if result.status == ScanStatus.FAILED)
    total_findings = sum(
        len(result.findings)
        for result in results
        if result.status == ScanStatus.SUCCESS
    )
    scans = []
    dependency_inventory = []
    scope_records = []
    for result in results:
        scan = {
            "scanner": result.scanner,
            "status": result.status.value,
            "message": result.message,
            "findings": (
                [_serialize_finding(finding) for finding in result.findings]
                if result.status == ScanStatus.SUCCESS
                else []
            ),
        }
        if result.dependencies:
            scan["dependencies"] = result.dependencies
            for dependency in result.dependencies:
                if dependency not in dependency_inventory:
                    dependency_inventory.append(dependency)
        if result.scope:
            scan["scope"] = result.scope
            scope_records.append(result.scope)
        scans.append(scan)

    scope_statuses = {
        str(scope.get("coverage_status", "unknown"))
        for scope in scope_records
        if isinstance(scope, dict)
    }
    if not results:
        coverage_status = "unknown"
    elif len(scope_records) != len(results):
        coverage_status = "unknown" if not scope_records else "incomplete"
    elif "incomplete" in scope_statuses or "unknown" in scope_statuses:
        coverage_status = "incomplete"
    else:
        coverage_status = "complete"
    scope_scanners = [
        {
            "scanner": result.scanner,
            "status": result.status.value,
            "scanner_execution_status": (
                result.scope.get("scanner_execution_status", result.status.value)
                if result.scope else result.status.value
            ),
            "coverage_status": (
                result.scope.get("coverage_status", "unknown")
                if result.scope else "unknown"
            ),
            "security_scan_coverage": (
                result.scope.get("security_scan_coverage", result.scope.get("coverage_status", "unknown"))
                if result.scope else "unknown"
            ),
            "dependency_files": (
                result.scope.get("dependency_files", [])
                if result.scope else []
            ),
            "ecosystems": (
                result.scope.get("ecosystems", [])
                if result.scope else []
            ),
            "inventory_available": bool(
                result.scope.get("inventory_available", bool(result.dependencies))
                if result.scope else bool(result.dependencies)
            ),
            "dependency_coverage": (
                result.scope.get("dependency_coverage", {})
                if result.scope else {}
            ),
        }
        for result in results
    ]

    report = {
        "tool": "CyberNest",
        "report_version": "1.3",
        "scanned_at": datetime.now().astimezone().isoformat(),
        "summary": {
            "total_scanners": len(results),
            "successful": successful,
            "skipped": skipped,
            "failed": failed,
            "total_findings": total_findings,
        },
        "scans": scans,
        "scan_scope": {
            "coverage_status": coverage_status,
            "security_scan_coverage": coverage_status,
            "scanners": scope_scanners,
            "dependency_files": sorted({
                str(path)
                for scope in scope_records
                for path in scope.get("dependency_files", [])
                if isinstance(path, str)
            }),
            "ecosystems": sorted({
                str(ecosystem)
                for scope in scope_records
                for ecosystem in scope.get("ecosystems", [])
                if isinstance(ecosystem, str)
            }),
        },
        "dependency_inventory": dependency_inventory,
    }
    report["scanner_execution_status"] = [
        {"scanner": item["scanner"], "status": item["status"]}
        for item in scope_scanners
    ]
    python_fields = (
        "python_target", "python_target_source", "python_target_confidence",
        "python_requires", "resolver_python_version", "python_scan_status",
    )
    scanner_python = {
        key: sorted({
            str(result.scope.get(key, ""))
            for result in results
            if result.scope and result.scope.get(key) not in (None, "")
        })
        for key in python_fields
    }
    report["scan_metadata"] = {
        "target": str(target.resolve()) if target is not None else "",
        "scanned_at": report["scanned_at"],
        "host_python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "platform": platform.system(),
        "architecture": platform.machine(),
        **{
            key: values[0] if len(values) == 1 else ("unknown" if not values else values)
            for key, values in scanner_python.items()
        },
    }
    report["scanner_results"] = scans
    report["findings"] = [
        {"scanner": scan["scanner"], **finding}
        for scan in scans
        if scan["status"] == ScanStatus.SUCCESS.value
        for finding in scan["findings"]
    ]
    severity_names = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN")
    report["severity_summary"] = {
        name: sum(1 for item in report["findings"] if item.get("severity", "UNKNOWN").upper() == name)
        for name in severity_names
    }
    warnings = []
    for scan in scans:
        scope = scan.get("scope", {})
        if isinstance(scope, dict):
            warnings.extend(scope.get("warnings", []))
        if scan["status"] != ScanStatus.SUCCESS.value:
            warnings.append(f"{scan['scanner']}: {scan['status']} - {scan['message']}")
    report["warnings"] = list(dict.fromkeys(value for value in warnings if isinstance(value, str) and value))
    if target is not None:
        report["target"] = str(target.resolve())
    if fix_plan is not None:
        recommendations = fix_plan.get("recommendations", [])
        report["fix_summary"] = {
            "packages_with_recommendations": sum(
                1 for item in recommendations if item.get("suggested_version")
            ),
            "compatible_plans": sum(
                1 for item in recommendations
                if item.get("compatibility_status") == "compatible"
            ),
            "unresolved_conflicts": sum(
                1 for item in recommendations
                if item.get("compatibility_status") == "incompatible"
            ),
            "plan_status": fix_plan.get("status", "unknown"),
        }
        report["fix_plan"] = fix_plan
        report["fix_plan_resolution_status"] = fix_plan.get(
            "dependency_resolution_status",
            fix_plan.get("dependency_resolution", "unknown"),
        )
        report["fix_recommendations"] = recommendations
        report["warnings"] = list(dict.fromkeys([
            *report["warnings"],
            *(value for value in fix_plan.get("warnings", []) if isinstance(value, str)),
            *(value for item in recommendations for value in item.get("warnings", []) if isinstance(value, str)),
        ]))
    if verification is not None:
        report["verification"] = verification
        report["warnings"] = list(dict.fromkeys([
            *report["warnings"],
            *(value for value in verification.get("warnings", []) if isinstance(value, str)),
        ]))
    return report
