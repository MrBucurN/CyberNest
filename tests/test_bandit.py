import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cybernest.integrations.bandit import BanditScanner
from cybernest.scan_result import ScanStatus


class TestBanditScanner(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.target = Path(self.temporary_directory.name)

    def add_python_file(self, relative_path="app.py"):
        path = self.target / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("print('example')\n", encoding="utf-8")
        return path

    @staticmethod
    def bandit_report(*, results=None, errors=None):
        return json.dumps({"results": results or [], "errors": errors or []})

    def test_no_python_files_is_skipped_without_starting_bandit(self):
        with patch("cybernest.integrations.bandit.subprocess.run") as run:
            result = BanditScanner().scan_with_status(self.target)

        self.assertEqual(result.status, ScanStatus.SKIPPED)
        self.assertEqual(result.scope["coverage_status"], "incomplete")
        run.assert_not_called()

    def test_bandit_finding_is_mapped_to_a_source_finding(self):
        self.add_python_file()
        report = self.bandit_report(
            results=[
                {
                    "filename": "app.py",
                    "issue_text": "Possible use of hard-coded password.",
                    "issue_severity": "HIGH",
                    "test_id": "B105",
                    "test_name": "hardcoded_password_string",
                    "line_number": 12,
                    "more_info": "https://bandit.readthedocs.io/",
                }
            ]
        )
        completed = subprocess.CompletedProcess([], 1, report, "")

        with patch(
            "cybernest.integrations.bandit.subprocess.run", return_value=completed
        ) as run:
            result = BanditScanner().scan_with_status(self.target)

        self.assertEqual(result.status, ScanStatus.SUCCESS)
        self.assertEqual(result.scope["coverage_status"], "complete")
        self.assertEqual(result.scope["source_files_scanned"], 1)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.title, "Possible use of hard-coded password.")
        self.assertEqual(finding.severity, "HIGH")
        self.assertEqual(finding.category, "source_code")
        self.assertEqual(finding.file_path, "app.py")
        self.assertEqual(finding.line_number, 12)
        self.assertEqual(finding.evidence, "B105 hardcoded_password_string")
        command = run.call_args.args[0]
        self.assertEqual(command[:3], [sys.executable, "-m", "bandit"])
        self.assertIn(".venv", command[command.index("-x") + 1])
        self.assertEqual(run.call_args.kwargs["cwd"], self.target)

    def test_no_findings_is_a_successful_complete_scan(self):
        self.add_python_file()
        completed = subprocess.CompletedProcess(
            [], 0, self.bandit_report(), ""
        )
        with patch(
            "cybernest.integrations.bandit.subprocess.run", return_value=completed
        ):
            result = BanditScanner().scan_with_status(self.target)

        self.assertEqual(result.status, ScanStatus.SUCCESS)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.scope["coverage_status"], "complete")

    def test_virtual_environment_sources_are_not_counted(self):
        self.add_python_file()
        self.add_python_file(".venv/lib/site-packages/library.py")
        completed = subprocess.CompletedProcess(
            [], 0, self.bandit_report(), ""
        )
        with patch(
            "cybernest.integrations.bandit.subprocess.run", return_value=completed
        ):
            result = BanditScanner().scan_with_status(self.target)

        self.assertEqual(result.scope["source_files_scanned"], 1)

    def test_bandit_file_errors_mark_coverage_incomplete(self):
        self.add_python_file()
        completed = subprocess.CompletedProcess(
            [],
            0,
            self.bandit_report(errors=[{"filename": "broken.py", "reason": "syntax error"}]),
            "",
        )
        with patch(
            "cybernest.integrations.bandit.subprocess.run", return_value=completed
        ):
            result = BanditScanner().scan_with_status(self.target)

        self.assertEqual(result.status, ScanStatus.SUCCESS)
        self.assertEqual(result.scope["coverage_status"], "incomplete")

    def test_bandit_process_error_is_reported_as_failed(self):
        self.add_python_file()
        completed = subprocess.CompletedProcess([], 2, "", "Bandit failed")
        with patch(
            "cybernest.integrations.bandit.subprocess.run", return_value=completed
        ):
            result = BanditScanner().scan_with_status(self.target)

        self.assertEqual(result.status, ScanStatus.FAILED)
        self.assertEqual(result.message, "Bandit failed")

    def test_bandit_timeout_is_reported_as_failed(self):
        self.add_python_file()
        with patch(
            "cybernest.integrations.bandit.subprocess.run",
            side_effect=subprocess.TimeoutExpired("bandit", 120),
        ):
            result = BanditScanner().scan_with_status(self.target)

        self.assertEqual(result.status, ScanStatus.FAILED)
        self.assertIn("timed out", result.message)

    def test_missing_target_is_reported_as_failed(self):
        result = BanditScanner().scan_with_status(self.target / "missing")

        self.assertEqual(result.status, ScanStatus.FAILED)
        self.assertEqual(result.scope["coverage_status"], "unknown")


if __name__ == "__main__":
    unittest.main()
