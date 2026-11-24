from dataclasses import asdict, dataclass, field


@dataclass
class FixRecommendation:
    package_name: str
    installed_version: str
    suggested_version: str | None = None
    resolved_version: str = ""
    declared_specifier: str = ""
    dependency_type: str = "unknown"
    affected_advisories: list[str] = field(default_factory=list)
    advisory_aliases: dict[str, list[str]] = field(default_factory=dict)
    advisories: list[dict[str, object]] = field(default_factory=list)
    addressed_advisories: list[str] = field(default_factory=list)
    remaining_advisories: list[str] = field(default_factory=list)
    unverified_advisories: list[str] = field(default_factory=list)
    security_coverage_status: str = "unknown"
    release_validation_status: str = "unverified"
    candidate_validations: list[dict[str, object]] = field(default_factory=list)
    candidate_audit_status: str = "not_run"
    candidate_audit_source: str = ""
    new_advisories: list[str] = field(default_factory=list)
    compatibility_status: str = "unknown"
    recommendation_status: str = "requires_manual_review"
    reason: str = ""
    warnings: list[str] = field(default_factory=list)
    requires_python: str = ""

    @property
    def status(self) -> str:
        if self.recommendation_status == "recommended":
            return "complete"
        if self.recommendation_status == "partial":
            return "partial"
        if self.recommendation_status == "no_known_fix":
            return "no_known_fix"
        if self.security_coverage_status == "unverified":
            return "unknown"
        return "manual_review"

    def to_dict(self) -> dict:
        data = asdict(self)
        data["status"] = self.status
        return data


@dataclass
class FixPlan:
    status: str = "unknown"
    python_target: str = "unknown"
    python_target_source: str = "unknown"
    python_target_confidence: str = "unknown"
    python_requires: str = ""
    python_target_conflict: bool = False
    recommendations: list[FixRecommendation] = field(default_factory=list)
    dependency_resolution: str = "not_run"
    dependency_resolution_status: str = "not_run"
    dependency_resolution_detail: str = ""
    dependency_resolution_evidence: dict[str, object] = field(default_factory=dict)
    dependency_changes: list[dict[str, str | None]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "python_target": self.python_target,
            "python_target_source": self.python_target_source,
            "python_target_confidence": self.python_target_confidence,
            "python_requires": self.python_requires,
            "python_target_conflict": self.python_target_conflict,
            "recommendations": [item.to_dict() for item in self.recommendations],
            "dependency_resolution": self.dependency_resolution,
            "dependency_resolution_status": self.dependency_resolution_status,
            "dependency_resolution_detail": self.dependency_resolution_detail,
            "dependency_resolution_evidence": self.dependency_resolution_evidence,
            "dependency_changes": self.dependency_changes,
            "warnings": self.warnings,
        }
