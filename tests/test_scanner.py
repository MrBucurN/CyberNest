
import unittest
from pathlib import Path

from cybernest.finding import Finding
from cybernest.integrations.base import BaseScanner


class ExampleScanner(BaseScanner):
    name = "example-scanner"

    def scan(self, target: Path) -> list[Finding]:
        return [
            Finding(
                title="Example vulnerability",
                severity="HIGH",
                tool=self.name,
                category="dependency",
            )
        ]


class TestBaseScanner(unittest.TestCase):

    def test_scanner_returns_findings(self):
        scanner = ExampleScanner()
        results = scanner.scan(Path("."))

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], Finding)
        self.assertEqual(results[0].tool, "example-scanner")


if __name__ == "__main__":
    unittest.main()
