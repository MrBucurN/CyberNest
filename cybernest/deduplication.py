import math
from dataclasses import replace

from cybernest.finding import Finding


def _cvss_source_priority(source: str) -> int:
    normalized = source.strip().lower()
    if normalized == "nvd":
        return 4
    if normalized.startswith("github advisory database"):
        return 3
    if normalized.startswith("nvd (primary:"):
        return 2
    if normalized.startswith("nvd (secondary:"):
        return 1
    return 0


def _cvss_version_priority(version: str) -> int:
    return {"4.0": 4, "3.1": 3, "3.0": 2, "2.0": 1}.get(version, 0)


def _cvss_quality(finding: Finding) -> tuple[int, int]:
    """Prefer NVD primary, then GitHub, other NVD primary, then secondary.

    CVSS version breaks ties within the same source tier.
    """
    return (
        _cvss_source_priority(finding.severity_source),
        _cvss_version_priority(finding.cvss_version),
    )


def _has_valid_cvss(finding: Finding) -> bool:
    score = finding.cvss_score
    return (
        isinstance(score, (int, float))
        and not isinstance(score, bool)
        and math.isfinite(score)
        and 0 <= score <= 10
        and bool(finding.cvss_version)
        and bool(finding.cvss_vector)
        and bool(finding.severity_source)
    )


def _lookup_status_priority(status: str) -> int:
    return {
        "resolved": 5,
        "rate_limited": 4,
        "network_error": 3,
        "api_error": 2,
        "not_available": 1,
    }.get(status, 0)


def _merge_severity_metadata(original: Finding, incoming: Finding) -> None:
    original_has_score = _has_valid_cvss(original)
    incoming_has_score = _has_valid_cvss(incoming)

    if incoming_has_score and (
        not original_has_score or _cvss_quality(incoming) > _cvss_quality(original)
    ):
        original.cvss_score = incoming.cvss_score
        original.cvss_vector = incoming.cvss_vector
        original.cvss_version = incoming.cvss_version
        original.severity_source = incoming.severity_source
        original.severity_source_url = incoming.severity_source_url
        original.severity = incoming.severity
        original.severity_lookup_status = incoming.severity_lookup_status or "resolved"
        original.reported_severity = incoming.reported_severity
        original.severity_selection_reason = incoming.severity_selection_reason
    elif not original_has_score and original.severity == "UNKNOWN":
        if incoming.severity != "UNKNOWN":
            original.severity = incoming.severity
        if not original.severity_source and incoming.severity_source:
            original.severity_source = incoming.severity_source
            original.severity_source_url = incoming.severity_source_url
            original.cvss_vector = incoming.cvss_vector
            original.cvss_version = incoming.cvss_version
            original.reported_severity = incoming.reported_severity
            original.severity_selection_reason = incoming.severity_selection_reason

    if _lookup_status_priority(incoming.severity_lookup_status) > _lookup_status_priority(
        original.severity_lookup_status
    ):
        original.severity_lookup_status = incoming.severity_lookup_status
    if incoming.applicability_status == "requires_review":
        if original.applicability_status != "requires_review":
            original.applicability_status = "requires_review"
            original.applicability_reason = incoming.applicability_reason


def _merge_descriptions(original: Finding, descriptions: list[str]) -> None:
    for description in descriptions:
        if not description:
            continue
        if not original.description:
            original.description = description
        elif (
            description != original.description
            and description not in original.additional_descriptions
        ):
            original.additional_descriptions.append(description)


def _merge_fix_versions(original: Finding, versions: list[str]) -> None:
    existing_versions = {
        version.strip()
        for version in original.fixed_version.split(",")
        if version.strip()
    }
    existing_versions.update(
        version.strip()
        for version in original.additional_fix_versions
        if version.strip()
    )

    for value in versions:
        for version in value.split(","):
            version = version.strip()
            if not version or version in existing_versions:
                continue
            if not original.fixed_version:
                original.fixed_version = version
            else:
                original.additional_fix_versions.append(version)
            existing_versions.add(version)


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings while retaining distinct descriptions."""
    seen: dict[tuple[str, str, str, str], Finding] = {}
    unique_findings = []

    for finding in findings:
        key = (
            finding.tool,
            finding.affected_component,
            finding.installed_version,
            finding.title,
        )
        if key not in seen:
            copied = replace(
                finding,
                additional_descriptions=[],
                additional_fix_versions=[],
                advisory_ids=list(finding.advisory_ids),
                advisory_warnings=list(finding.advisory_warnings),
            )
            seen[key] = copied
            unique_findings.append(copied)
            _merge_descriptions(
                copied,
                [finding.description, *finding.additional_descriptions],
            )
            _merge_fix_versions(
                copied,
                [finding.fixed_version, *finding.additional_fix_versions],
            )
            continue

        original = seen[key]
        _merge_descriptions(
            original,
            [finding.description, *finding.additional_descriptions],
        )
        _merge_fix_versions(
            original,
            [finding.fixed_version, *finding.additional_fix_versions],
        )
        _merge_severity_metadata(original, finding)
        for advisory_id in finding.advisory_ids:
            if advisory_id and advisory_id not in original.advisory_ids:
                original.advisory_ids.append(advisory_id)
        for warning in finding.advisory_warnings:
            if warning and warning not in original.advisory_warnings:
                original.advisory_warnings.append(warning)

    return unique_findings
