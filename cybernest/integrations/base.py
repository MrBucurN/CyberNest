
from abc import ABC, abstractmethod
from pathlib import Path

from cybernest.finding import Finding


class BaseScanner(ABC):
    """Common interface for scanners."""

    name = "unknown"

    @abstractmethod
    def scan(self, target: Path) -> list[Finding]:
        """Scan a project and return findings."""
        pass
