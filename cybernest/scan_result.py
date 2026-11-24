
from dataclasses import dataclass, field
from enum import Enum

from cybernest.finding import Finding


class ScanStatus(str, Enum):
    SUCCESS = "success"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass
class ScanResult:
    scanner: str
    status: ScanStatus
    findings: list[Finding] = field(default_factory=list)
    message: str = ""
    dependencies: list[dict[str, str]] = field(default_factory=list)
    scope: dict[str, object] = field(default_factory=dict)
