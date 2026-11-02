
import unittest

from cybernest.scan_result import ScanResult, ScanStatus


class TestScanResult(unittest.TestCase):

    def test_success_result(self):
        result = ScanResult(
            scanner="pip-audit",
            status=ScanStatus.SUCCESS,
        )

        self.assertEqual(result.scanner, "pip-audit")
        self.assertEqual(result.status, ScanStatus.SUCCESS)
        self.assertEqual(result.findings, [])

    def test_skipped_result(self):
        result = ScanResult(
            scanner="pip-audit",
            status=ScanStatus.SKIPPED,
            message="requirements.txt not found",
        )

        self.assertEqual(result.status, ScanStatus.SKIPPED)
        self.assertIn("requirements.txt", result.message)

    def test_failed_result(self):
        result = ScanResult(
            scanner="pip-audit",
            status=ScanStatus.FAILED,
            message="Scanner execution failed",
        )

        self.assertEqual(result.status, ScanStatus.FAILED)

    def test_results_have_independent_finding_lists(self):
        first = ScanResult("scanner-a", ScanStatus.SUCCESS)
        second = ScanResult("scanner-b", ScanStatus.SUCCESS)

        self.assertIsNot(first.findings, second.findings)


if __name__ == "__main__":
    unittest.main()
