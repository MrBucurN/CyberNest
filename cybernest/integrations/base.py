
from abc import ABC, abstractmethod
from pathlib import Path

from cybernest.finding import Finding


class BaseScanner(ABC):
    """Tüm CyberNest tarama araçlarının ortak arayüzü."""

    name = "unknown"

    @abstractmethod
    def scan(self, target: Path) -> list[Finding]:
        """Hedef projeyi tarar ve standart bulgular döndürür."""
        pass
