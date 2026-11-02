import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cybernest import main as main_module
from cybernest.finding import Finding
from cybernest.fixes.models import FixPlan, FixRecommendation
from cybernest.scan_result import ScanResult, ScanStatus


class FakeEngine:
    def __init__(self, results, findings=None):
        self.results = results
        self.findings = findings if findings is not None else []

    def register(self, scanner):
        pass

    def scan(self, target: Path):
        return self.findings


class TestMain(unittest.TestCase):

    def run_main_with_results(
        self, results, findings=None, output_path=None, verbose=False, overwrite=False
    ):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as temp_dir:
            engine = FakeEngine(results, findings)
            argv = ["main.py", temp_dir]
            if output_path is not None:
                argv.extend(["--output", str(output_path)])
            if verbose:
                argv.append("--verbose")
            if overwrite:
                argv.append("--overwrite")
            with patch.object(main_module, "ScanEngine", return_value=engine):
                with patch.object(sys, "argv", argv):
                    with contextlib.redirect_stdout(output):
                        main_module.main()
        return output.getvalue()

    def test_summary_displays_scanner_status_message_and_findings(self):
        output = self.run_main_with_results(
            [
                ScanResult(
                    scanner="pip-audit",
                    status=ScanStatus.SKIPPED,
                    message="requirements.txt not found.",
                )
            ]
        )

        self.assertIn("Scanner: pip-audit", output)
        self.assertIn("Status: SKIPPED", output)
        self.assertIn("Message: requirements.txt not found.", output)
        self.assertIn("Findings: 0", output)
        self.assertIn("results are inconclusive", output)
        self.assertNotIn("No known vulnerabilities", output)

    def test_no_vulnerabilities_reported_only_after_successful_scan(self):
        output = self.run_main_with_results(
            [
                ScanResult(
                    scanner="pip-audit",
                    status=ScanStatus.SUCCESS,
                    message="Scan completed successfully.",
                    scope={
                        "coverage_status": "complete",
                        "dependency_coverage": {"scanned_dependency_count": 2},
                    },
                )
            ]
        )

        self.assertIn("Status: SUCCESS", output)
        self.assertIn("No known vulnerabilities reported among 2 scanned", output)

    def test_cvss_source_is_default_but_vector_and_url_require_verbose(self):
        finding = Finding(
            title="CVE-2026-1234",
            severity="HIGH",
            tool="pip-audit",
            category="dependency",
            affected_component="example-package",
            cvss_score=8.1,
            cvss_version="3.1",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            severity_source="NVD",
            severity_source_url="https://nvd.nist.gov/example",
            severity_lookup_status="resolved",
        )
        result = ScanResult(
            scanner="pip-audit",
            status=ScanStatus.SUCCESS,
            findings=[finding],
            scope={"coverage_status": "complete"},
        )

        standard = self.run_main_with_results([result], findings=[finding])
        verbose = self.run_main_with_results([result], findings=[finding], verbose=True)

        self.assertIn("Source: NVD", standard)
        self.assertNotIn("CVSS:3.1/AV:N", standard)
        self.assertNotIn("Source URL:", standard)
        self.assertIn("CVSS:3.1/AV:N", verbose)
        self.assertIn("Source URL: https://nvd.nist.gov/example", verbose)

    def test_partial_success_displays_findings_and_incomplete_warning(self):
        finding = Finding(
            title="Example vulnerability",
            severity="HIGH",
            tool="successful-scanner",
            category="dependency",
        )
        output = self.run_main_with_results(
            [
                ScanResult(
                    scanner="successful-scanner",
                    status=ScanStatus.SUCCESS,
                    findings=[finding],
                    message="Scan completed successfully.",
                ),
                ScanResult(
                    scanner="failed-scanner",
                    status=ScanStatus.FAILED,
                    message="Scanner unavailable.",
                ),
            ],
            findings=[finding],
            verbose=True,
        )

        self.assertIn("Found 1 security finding", output)
        self.assertIn("[HIGH]  : Example vulnerability", output)
        self.assertIn("Tool: successful-scanner", output)
        self.assertIn(
            "[WARNING] Some security checks were skipped or failed.", output
        )
        self.assertIn("The security assessment is incomplete.", output)

    def test_no_scanners_executed_is_reported_as_incomplete(self):
        output = self.run_main_with_results([])

        self.assertIn("No scanners executed.", output)
        self.assertIn("[WARNING] No security checks were executed.", output)
        self.assertIn("The security assessment is incomplete.", output)
        self.assertNotIn("No known vulnerabilities reported", output)

    def test_output_option_saves_scan_report(self):
        result = ScanResult(
            scanner="pip-audit",
            status=ScanStatus.SUCCESS,
            message="Scan completed successfully.",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "report.json"
            output = self.run_main_with_results([result], output_path=output_path)

            saved_report = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(saved_report["summary"]["successful"], 1)
        self.assertEqual(saved_report["scans"][0]["scanner"], "pip-audit")
        self.assertIn(f"Report saved: {output_path}", output)

    def test_overwrite_option_replaces_existing_report_explicitly(self):
        result = ScanResult(
            scanner="pip-audit",
            status=ScanStatus.SUCCESS,
            message="Scan completed successfully.",
            scope={"coverage_status": "complete"},
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir)
            output_path = target / "report.json"
            output_path.write_text('{"old": true}', encoding="utf-8")

            output = self.run_main_with_results(
                [result], output_path=output_path, overwrite=True
            )

            report = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(report["report_version"], "1.2")
        self.assertNotIn("old", report)
        self.assertIn("Report saved", output)

    def test_exit_codes_distinguish_clean_findings_and_incomplete_scans(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir)
            cases = [
                ([], ScanResult(
                    scanner="pip-audit", status=ScanStatus.SUCCESS,
                    scope={"coverage_status": "complete"},
                ), 0),
                ([Finding(
                    title="CVE-2026-1234", severity="HIGH",
                    tool="pip-audit", category="dependency",
                )], ScanResult(
                    scanner="pip-audit", status=ScanStatus.SUCCESS,
                    findings=[], scope={"coverage_status": "complete"},
                ), 1),
                ([], ScanResult(
                    scanner="pip-audit", status=ScanStatus.SUCCESS,
                    scope={"coverage_status": "incomplete"},
                ), 3),
            ]
            for findings, result, expected in cases:
                with self.subTest(expected=expected):
                    engine = FakeEngine([result], findings)
                    with patch.object(main_module, "ScanEngine", return_value=engine):
                        with patch.object(sys, "argv", ["main.py", str(target)]):
                            with contextlib.redirect_stdout(io.StringIO()):
                                self.assertEqual(main_module.main(), expected)

    def test_cli_usage_error_uses_argparse_exit_code(self):
        with patch.object(sys, "argv", ["main.py"]):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    main_module.main()
        self.assertEqual(error.exception.code, 2)

    def test_output_error_is_reported_and_exits_unsuccessfully(self):
        result = ScanResult(
            scanner="pip-audit",
            status=ScanStatus.SUCCESS,
            message="Scan completed successfully.",
        )
        output = io.StringIO()

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "report.json"
            output_path.write_text("existing report", encoding="utf-8")
            engine = FakeEngine([result])
            with patch.object(main_module, "ScanEngine", return_value=engine):
                with patch.object(
                    sys,
                    "argv",
                    ["main.py", temp_dir, "--output", str(output_path)],
                ):
                    with contextlib.redirect_stdout(output):
                        with self.assertRaises(SystemExit) as exit_error:
                            main_module.main()

            self.assertEqual(
                output_path.read_text(encoding="utf-8"),
                "existing report",
            )

            self.assertEqual(exit_error.exception.code, 4)
        self.assertIn("Report already exists", output.getvalue())
        self.assertIn("--overwrite explicitly", output.getvalue())

    def test_output_os_error_is_reported_and_exits_unsuccessfully(self):
        result = ScanResult(
            scanner="pip-audit",
            status=ScanStatus.SUCCESS,
            message="Scan completed successfully.",
        )
        output = io.StringIO()

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "missing" / "report.json"
            engine = FakeEngine([result])
            with patch.object(main_module, "ScanEngine", return_value=engine):
                with patch.object(
                    sys,
                    "argv",
                    ["main.py", temp_dir, "--output", str(output_path)],
                ):
                    with contextlib.redirect_stdout(output):
                        with self.assertRaises(SystemExit) as exit_error:
                            main_module.main()

        self.assertEqual(exit_error.exception.code, 4)
        self.assertIn("Unable to save report to", output.getvalue())

    def test_suggest_fixes_is_opt_in_and_saved_to_report(self):
        result = ScanResult(
            scanner="pip-audit",
            status=ScanStatus.SUCCESS,
            findings=[],
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir)
            output_path = target / "report.json"
            plan = FixPlan(status="partial", recommendations=[
                FixRecommendation(
                    package_name="flask",
                    installed_version="1.1.2",
                    suggested_version="2.2.5",
                    compatibility_status="unknown",
                    recommendation_status="recommended",
                    advisory_aliases={"CVE-2023-30861": ["GHSA-M2QF-HXJV-5GPQ", "PYSEC-2023-62"]},
                )
            ])
            output = io.StringIO()
            engine = FakeEngine([result], [])
            with patch.object(main_module, "ScanEngine", return_value=engine):
                with patch.object(main_module.FixRecommender, "build_plan", return_value=plan):
                    with patch.object(
                        sys,
                        "argv",
                        ["main.py", temp_dir, "--suggest-fixes", "--output", str(output_path)],
                    ):
                        with contextlib.redirect_stdout(output):
                            main_module.main()
            saved_report = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertIn("Plan status: partial", output.getvalue())
        self.assertNotIn("Aliases for CVE-2023-30861", output.getvalue())
        self.assertLess(
            output.getvalue().index("SCAN SUMMARY"),
            output.getvalue().index("FIX PLAN"),
        )
        self.assertLess(
            output.getvalue().index("FIX PLAN"),
            output.getvalue().index("Report saved:"),
        )
        self.assertEqual(saved_report["fix_plan"]["recommendations"][0]["suggested_version"], "2.2.5")
        self.assertEqual(
            saved_report["fix_plan"]["recommendations"][0]["advisory_aliases"]["CVE-2023-30861"],
            ["GHSA-M2QF-HXJV-5GPQ", "PYSEC-2023-62"],
        )
        self.assertEqual(saved_report["target"], str(target.resolve()))

    def test_compare_option_keeps_legacy_previous_report_inconclusive(self):
        old_finding = {
            "title": "PYSEC-TEST-1",
            "affected_component": "flask",
            "advisory_ids": ["PYSEC-TEST-1"],
        }
        result = ScanResult(
            scanner="pip-audit",
            status=ScanStatus.SUCCESS,
            findings=[],
        )
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir)
            previous_path = target / "previous.json"
            previous_path.write_text(json.dumps({
                "target": str(target.resolve()),
                "scans": [{"scanner": "pip-audit", "status": "success", "findings": [old_finding]}],
            }), encoding="utf-8")
            engine = FakeEngine([result], [])
            with patch.object(main_module, "ScanEngine", return_value=engine):
                with patch.object(
                    sys,
                    "argv",
                    ["main.py", temp_dir, "--compare", str(previous_path)],
                ):
                    with contextlib.redirect_stdout(output):
                        main_module.main()

        self.assertIn("Status: inconclusive", output.getvalue())
        self.assertIn("Resolved: 0", output.getvalue())
        self.assertIn("Legacy reports", output.getvalue())
        self.assertLess(
            output.getvalue().index("SCAN SUMMARY"),
            output.getvalue().index("FIX VERIFICATION"),
        )


if __name__ == "__main__":
    unittest.main()
