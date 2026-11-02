
from dataclasses import dataclass, field


@dataclass
class Finding:
    """CyberNest'in ortak güvenlik bulgusu modeli."""

    title: str
    severity: str
    tool: str
    category: str
    description: str = ""
    affected_component: str = ""
    installed_version: str = ""
    # For manifest-based scans, pip-audit resolves a version; it is not an
    # assertion that the package is installed in the user's environment.
    resolved_version: str = ""
    declared_specifier: str = ""
    dependency_source: str = ""
    dependency_direct: bool | None = None
    applicability_status: str = "unknown"
    applicability_reason: str = ""
    fixed_version: str = ""
    advisory_url: str = ""
    evidence: str = ""
    recommendation: str = ""
    file_path: str = ""
    additional_descriptions: list[str] = field(default_factory=list)
    additional_fix_versions: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str = ""
    severity_source: str = ""
    severity_source_url: str = ""
    cvss_version: str = ""
    severity_lookup_status: str = ""
    severity_data_origin: str = ""
    severity_cache_age_seconds: float | None = None
    reported_severity: str = ""
    severity_selection_reason: str = ""
    advisory_ids: list[str] = field(default_factory=list)
    advisory_warnings: list[str] = field(default_factory=list)
