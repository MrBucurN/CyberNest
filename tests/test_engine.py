
import unittest
from pathlib import Path

from cybernest.engine import ScanEngine
from cybernest.finding import Finding
from cybernest.integrations.base import BaseScanner
from cybernest.scan_result import ScanResult, ScanStatus


class FakeScanner(BaseScanner):
    name = "fake-scanner"

    def scan(self, target: Path) -> list[Finding]:
        return [
            Finding(
                title="Test finding",
                severity="LOW",
                tool=self.name,
                category="test",
            )
        ]


class TestScanEngine(unittest.TestCase):

    def test_engine_collects_findings(self):
        engine = ScanEngine()
        engine.register(FakeScanner())
        engine.register(FakeScanner())

        findings = engine.scan(Path("."))

        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].title, "Test finding")
        self.assertEqual(len(engine.results), 2)
        self.assertTrue(
            all(result.status == ScanStatus.SUCCESS for result in engine.results)
        )


class StatusScanner(BaseScanner):
    name = "status-scanner"

    def __init__(self, status: ScanStatus):
        self.status = status

    def scan(self, target: Path) -> list[Finding]:
        raise AssertionError("scan() should not be called")

    def scan_with_status(self, target: Path) -> ScanResult:
        findings = (
            [
                Finding(
                    title="Status finding",
                    severity="LOW",
                    tool=self.name,
                    category="test",
                )
            ]
            if self.status == ScanStatus.SUCCESS
            else []
        )
        return ScanResult(
            scanner=self.name,
            status=self.status,
            findings=findings,
            message=f"{self.status.value} message",
        )


class TestStatusScanEngine(unittest.TestCase):

    def test_successful_status_result_contributes_findings(self):
        engine = ScanEngine()
        engine.register(StatusScanner(ScanStatus.SUCCESS))

        findings = engine.scan(Path("."))

        self.assertEqual(len(findings), 1)
        self.assertEqual(engine.results[0].status, ScanStatus.SUCCESS)
        self.assertEqual(engine.errors, [])

    def test_failed_status_result_is_recorded_as_error(self):
        engine = ScanEngine()
        engine.register(StatusScanner(ScanStatus.FAILED))

        findings = engine.scan(Path("."))

        self.assertEqual(findings, [])
        self.assertEqual(engine.results[0].status, ScanStatus.FAILED)
        self.assertEqual(
            engine.errors,
            [{"scanner": "status-scanner", "message": "failed message"}],
        )

    def test_skipped_status_result_is_not_recorded_as_error(self):
        engine = ScanEngine()
        engine.register(StatusScanner(ScanStatus.SKIPPED))

        findings = engine.scan(Path("."))

        self.assertEqual(findings, [])
        self.assertEqual(engine.results[0].status, ScanStatus.SKIPPED)
        self.assertEqual(engine.errors, [])


class FailingScanner(BaseScanner):
    name = "failing-scanner"

    def scan(self, target: Path) -> list[Finding]:
        raise RuntimeError("Scanner crashed")


class TestEngineErrorHandling(unittest.TestCase):

    def test_engine_continues_after_scanner_failure(self):
        engine = ScanEngine()

        engine.register(FailingScanner())

        engine.register(FakeScanner())

        findings = engine.scan(Path("."))

        self.assertEqual(len(findings), 1)

        self.assertEqual(len(engine.errors), 1)
        self.assertEqual(
            engine.errors[0]["scanner"],
            "failing-scanner"
        )
        self.assertEqual(len(engine.results), 2)
        self.assertEqual(engine.results[0].status, ScanStatus.FAILED)
        self.assertEqual(engine.results[0].message, "Scanner crashed")

if __name__ == "__main__":
    unittest.main()
