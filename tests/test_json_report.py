import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from cybernest.finding import Finding
from cybernest.fixes.models import FixPlan, FixRecommendation
from cybernest.reports.json_report import build_report, save_report
from cybernest.scan_result import ScanResult, ScanStatus


class TestBuildReport(unittest.TestCase):

    def test_build_report_summarizes_scan_results(self):
        finding = Finding(
            title="Example vulnerability",
            severity="HIGH",
            tool="pip-audit",
            category="dependency",
        )
        results = [
            ScanResult(
                scanner="successful-scanner",
                status=ScanStatus.SUCCESS,
                findings=[finding],
            ),
            ScanResult(
                scanner="skipped-scanner",
                status=ScanStatus.SKIPPED,
            ),
            ScanResult(
                scanner="failed-scanner",
                status=ScanStatus.FAILED,
                findings=[finding],
            ),
        ]

        report = build_report(results)

        self.assertEqual(report["tool"], "CyberNest")
        self.assertEqual(report["report_version"], "1.3")
        scanned_at = datetime.fromisoformat(report["scanned_at"])
        self.assertIsNotNone(scanned_at.tzinfo)
        self.assertEqual(
            report["summary"],
            {
                "total_scanners": 3,
                "successful": 1,
                "skipped": 1,
                "failed": 1,
                "total_findings": 1,
            },
        )
        self.assertEqual(json.loads(json.dumps(report)), report)

    def test_build_report_handles_no_scan_results(self):
        report = build_report([])

        self.assertEqual(
            report["summary"],
            {
                "total_scanners": 0,
                "successful": 0,
                "skipped": 0,
                "failed": 0,
                "total_findings": 0,
            },
        )
        self.assertEqual(report["scans"], [])

    def test_build_report_includes_dependency_inventory(self):
        result = ScanResult(
            scanner="pip-audit",
            status=ScanStatus.SUCCESS,
            dependencies=[{"name": "Flask", "version": "1.1.2"}],
        )

        report = build_report([result])

        self.assertEqual(
            report["scans"][0]["dependencies"],
            [{"name": "Flask", "version": "1.1.2"}],
        )

    def test_build_report_records_scope_and_top_level_inventory(self):
        result = ScanResult(
            scanner="pip-audit",
            status=ScanStatus.SUCCESS,
            dependencies=[{"name": "Flask", "version": "1.1.2"}],
            scope={
                "coverage_status": "complete",
                "scanner_execution_status": "success",
                "security_scan_coverage": "complete",
                "dependency_files": ["requirements.txt"],
                "ecosystems": ["pypi"],
                "inventory_available": True,
                "dependency_coverage": {
                    "direct_dependencies": {"declared_count": 1, "scanned_count": 1},
                    "transitive_dependencies": {"scanned_count": 2, "status": "complete"},
                    "scanned_dependency_count": 3,
                },
            },
        )

        report = build_report([result])

        self.assertEqual(report["scan_scope"]["coverage_status"], "complete")
        self.assertEqual(report["scan_scope"]["dependency_files"], ["requirements.txt"])
        self.assertEqual(report["dependency_inventory"], [{"name": "Flask", "version": "1.1.2"}])
        self.assertEqual(report["scans"][0]["scope"]["ecosystems"], ["pypi"])
        self.assertEqual(report["scan_scope"]["security_scan_coverage"], "complete")
        self.assertEqual(
            report["scanner_execution_status"],
            [{"scanner": "pip-audit", "status": "success"}],
        )
        self.assertEqual(
            report["scan_scope"]["scanners"][0]["dependency_coverage"]["scanned_dependency_count"],
            3,
        )

    def test_build_report_includes_optional_fix_and_verification_sections(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir)
            fix_plan = {
                "status": "ready_for_review",
                "recommendations": [{
                    "package_name": "flask",
                    "suggested_version": "2.2.5",
                    "compatibility_status": "compatible",
                }],
                "dependency_resolution": "resolved",
                "dependency_resolution_status": "resolved",
                "dependency_changes": [{
                    "package_name": "werkzeug",
                    "previous_version": "1.0.1",
                    "selected_version": "2.3.8",
                    "change": "updated",
                }],
                "warnings": [],
            }
            verification = {
                "status": "resolved",
                "overall_status": "inconclusive",
                "scope_status": "matched",
                "resolved": [{"title": "PYSEC-TEST-1"}],
                "remaining": [],
                "new": [],
                "scoped_verification": {
                    "status": "resolved",
                    "scope": "direct_dependencies",
                    "resolved": [{"title": "CVE-2026-1234"}],
                    "warnings": ["Overall coverage remains incomplete."],
                },
            }

            report = build_report(
                [],
                target=target,
                fix_plan=fix_plan,
                verification=verification,
            )

        self.assertEqual(report["target"], str(target.resolve()))
        self.assertEqual(report["fix_summary"]["packages_with_recommendations"], 1)
        self.assertEqual(report["fix_summary"]["compatible_plans"], 1)
        self.assertEqual(report["fix_plan"], fix_plan)
        self.assertEqual(report["fix_plan_resolution_status"], "resolved")
        self.assertEqual(report["verification"], verification)
        self.assertEqual(report["verification"]["overall_status"], "inconclusive")
        self.assertEqual(report["verification"]["scoped_verification"]["status"], "resolved")

    def test_build_report_preserves_fix_validation_and_alias_metadata(self):
        recommendation = FixRecommendation(
            package_name="Flask",
            installed_version="1.1.2",
            suggested_version="2.2.5",
            affected_advisories=["CVE-2023-30861"],
            advisory_aliases={
                "CVE-2023-30861": ["GHSA-M2QF-HXJV-5GPQ", "PYSEC-2023-62"]
            },
            advisories=[{
                "canonical_id": "CVE-2023-30861",
                "aliases": ["GHSA-M2QF-HXJV-5GPQ", "PYSEC-2023-62"],
                "status": "addressed",
            }],
            addressed_advisories=["CVE-2023-30861"],
            security_coverage_status="complete",
            release_validation_status="verified",
            candidate_validations=[{
                "version": "2.2.5",
                "source": "PyPI JSON API",
                "status": "verified",
                "checked_at": "2026-11-01T00:00:00+00:00",
                "candidate_security_audit": {"status": "verified"},
            }],
            candidate_audit_status="verified",
            candidate_audit_source="pip-audit exact-pin audit",
            new_advisories=["CVE-2026-0001"],
            recommendation_status="recommended",
        )

        report = build_report(
            [], fix_plan=FixPlan(recommendations=[recommendation]).to_dict()
        )
        serialized = report["fix_plan"]["recommendations"][0]

        self.assertEqual(serialized["status"], "complete")
        self.assertEqual(serialized["advisory_aliases"], recommendation.advisory_aliases)
        self.assertEqual(serialized["candidate_validations"], recommendation.candidate_validations)
        self.assertEqual(serialized["candidate_audit_status"], "verified")
        self.assertEqual(serialized["candidate_audit_source"], "pip-audit exact-pin audit")
        self.assertEqual(serialized["new_advisories"], ["CVE-2026-0001"])
        self.assertEqual(serialized["release_validation_status"], "verified")

    def test_build_report_includes_each_scanner(self):
        results = [
            ScanResult("scanner-a", ScanStatus.SUCCESS, message="Completed."),
            ScanResult("scanner-b", ScanStatus.SKIPPED, message="Not applicable."),
        ]

        report = build_report(results)

        self.assertEqual(
            report["scans"],
            [
                {
                    "scanner": "scanner-a",
                    "status": "success",
                    "message": "Completed.",
                    "findings": [],
                },
                {
                    "scanner": "scanner-b",
                    "status": "skipped",
                    "message": "Not applicable.",
                    "findings": [],
                },
            ],
        )

    def test_build_report_serializes_finding_fields(self):
        finding = Finding(
            title="TEST-2026-001",
            severity="UNKNOWN",
            tool="pip-audit",
            category="dependency",
            affected_component="example-package",
            installed_version="1.0",
            fixed_version="1.1",
        )
        result = ScanResult(
            scanner="pip-audit",
            status=ScanStatus.SUCCESS,
            findings=[finding],
            message="Scan completed successfully.",
        )

        report = build_report([result])

        self.assertEqual(
            report["scans"][0]["findings"][0],
            {
                "title": "TEST-2026-001",
                "severity": "UNKNOWN",
                "tool": "pip-audit",
                "category": "dependency",
                "description": "",
                "affected_component": "example-package",
                "installed_version": "1.0",
                "applicability_status": "unknown",
                "applicability_reason": "",
                "fixed_version": "1.1",
                "advisory_url": "",
                "evidence": "",
                "recommendation": "",
                "file_path": "",
                "additional_descriptions": [],
                "additional_fix_versions": [],
            },
        )
        self.assertEqual(json.loads(json.dumps(report)), report)

    def test_build_report_preserves_source_line_number(self):
        finding = Finding(
            title="Possible insecure call.",
            severity="MEDIUM",
            tool="bandit",
            category="source_code",
            file_path="app.py",
            line_number=17,
        )

        report = build_report([
            ScanResult(
                scanner="bandit",
                status=ScanStatus.SUCCESS,
                findings=[finding],
            )
        ])

        saved_finding = report["scans"][0]["findings"][0]
        self.assertEqual(saved_finding["file_path"], "app.py")
        self.assertEqual(saved_finding["line_number"], 17)

    def test_build_report_includes_severity_lookup_metadata(self):
        finding = Finding(
            title="CVE-2023-30861",
            severity="HIGH",
            tool="pip-audit",
            category="dependency",
            cvss_score=8.1,
            cvss_vector="CVSS:3.1/example-vector",
            cvss_version="3.1",
            severity_source="NVD",
            severity_source_url="https://nvd.example/CVE-2023-30861",
            severity_lookup_status="resolved",
            severity_data_origin="cache",
            severity_cache_age_seconds=12.5,
            reported_severity="UNKNOWN",
            advisory_ids=[
                "PYSEC-2023-62",
                "CVE-2023-30861",
                "GHSA-m2qf-hxjv-5gpq",
            ],
        )

        serialized = build_report([
            ScanResult(
                scanner="pip-audit",
                status=ScanStatus.SUCCESS,
                findings=[finding],
            )
        ])["scans"][0]["findings"][0]

        self.assertEqual(serialized["cvss_score"], 8.1)
        self.assertEqual(serialized["cvss_vector"], "CVSS:3.1/example-vector")
        self.assertEqual(serialized["cvss_version"], "3.1")
        self.assertEqual(serialized["severity_source"], "NVD")
        self.assertEqual(
            serialized["severity_source_url"],
            "https://nvd.example/CVE-2023-30861",
        )
        self.assertEqual(serialized["severity_lookup_status"], "resolved")
        self.assertEqual(serialized["severity_data_origin"], "cache")
        self.assertEqual(serialized["severity_cache_age_seconds"], 12.5)
        self.assertEqual(serialized["reported_severity"], "UNKNOWN")
        self.assertEqual(serialized["canonical_id"], "CVE-2023-30861")
        self.assertEqual(
            serialized["aliases"],
            ["GHSA-M2QF-HXJV-5GPQ", "PYSEC-2023-62"],
        )

    def test_build_report_explains_unknown_severity_lookup(self):
        finding = Finding(
            title="CVE-2026-1234",
            severity="UNKNOWN",
            tool="pip-audit",
            category="dependency",
            severity_lookup_status="network_error",
        )

        serialized = build_report([
            ScanResult(
                scanner="pip-audit",
                status=ScanStatus.SUCCESS,
                findings=[finding],
            )
        ])["scans"][0]["findings"][0]

        self.assertIsNone(serialized["cvss_score"])
        self.assertEqual(serialized["severity"], "UNKNOWN")
        self.assertEqual(serialized["severity_lookup_status"], "network_error")

    def test_failed_scan_findings_are_not_reported(self):
        finding = Finding(
            title="Unverified vulnerability",
            severity="UNKNOWN",
            tool="failed-scanner",
            category="dependency",
        )
        result = ScanResult(
            scanner="failed-scanner",
            status=ScanStatus.FAILED,
            findings=[finding],
        )

        report = build_report([result])

        self.assertEqual(report["summary"]["total_findings"], 0)
        self.assertEqual(report["scans"][0]["findings"], [])


class TestSaveReport(unittest.TestCase):

    def test_save_report_creates_json_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "report.json"
            report = {
                "tool": "CyberNest",
                "message": "Security scan completed — no issues found.",
            }

            save_report(report, output_path)

            self.assertTrue(output_path.is_file())
            saved_data = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(saved_data, report)

    def test_save_report_writes_json_and_preserves_unicode_text(self):
        report = {"message": "Security scan completed — no issues found."}

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "report.json"
            save_report(report, output_path)

            contents = output_path.read_text(encoding="utf-8")

        self.assertIn("Security", contents)
        self.assertEqual(json.loads(contents), report)

    def test_save_report_does_not_overwrite_existing_file_with_existing_report(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "report.json"
            output_path.write_text("original content", encoding="utf-8")

            with self.assertRaises(FileExistsError):
                save_report({"tool": "CyberNest"}, output_path)

            self.assertEqual(
                output_path.read_text(encoding="utf-8"),
                "original content",
            )

    def test_save_report_rejects_missing_parent_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "missing" / "report.json"

            with self.assertRaises(FileNotFoundError):
                save_report({"tool": "CyberNest"}, output_path)

    def test_save_report_overwrites_only_when_explicit_and_writes_valid_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "report.json"
            output_path.write_text('{"old": true}', encoding="utf-8")

            save_report({"new": "Safe"}, output_path, overwrite=True)

            self.assertEqual(
                json.loads(output_path.read_text(encoding="utf-8")),
                {"new": "Safe"},
            )
            self.assertEqual(list(Path(temp_dir).glob(".cybernest-report-*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
