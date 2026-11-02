import unittest

from cybernest.fixes.verification import compare_reports


def report(target, findings, status="success", scanner="pip-audit"):
    packages = {}
    for item in findings:
        package = item.get("affected_component", "flask")
        packages[package.casefold()] = {
            "name": package,
            "version": item.get("installed_version", "1.1.2"),
            "resolved_version": item.get("installed_version", "1.1.2"),
            "direct": True,
            "source_file": "requirements.txt",
        }
    if not packages:
        packages["flask"] = {
            "name": "flask", "version": "1.1.2", "resolved_version": "1.1.2",
            "direct": True, "source_file": "requirements.txt",
        }
    dependency_items = list(packages.values())
    package_count = len(dependency_items)
    coverage = {
        "direct_dependencies": {
            "declared_count": package_count, "scanned_count": package_count,
            "not_applicable_count": 0, "unscanned_count": 0, "status": "complete",
        },
        "transitive_dependencies": {"scanned_count": 0, "status": "complete"},
        "target_context_status": "runtime_context",
        "unsupported_files": [],
        "manifests": [{
            "manifest": "requirements.txt", "status": "complete",
            "direct_dependencies_declared": package_count,
            "direct_dependencies_scanned": package_count,
            "direct_dependencies_not_applicable": 0,
            "direct_dependencies_unscanned": [],
            "direct_coverage_status": "complete",
        }],
    }
    scan = {
        "scanner": scanner, "status": status, "findings": findings,
        "dependencies": dependency_items,
        "scope": {
            "coverage_status": "complete", "dependency_files": ["requirements.txt"],
            "ecosystems": ["pypi"], "dependency_coverage": coverage,
        },
    }
    return {
        "tool": "CyberNest",
        "target": target,
        "scans": [scan],
        "scan_scope": {
            "coverage_status": "complete", "dependency_files": ["requirements.txt"],
            "ecosystems": ["pypi"],
            "scanners": [{
                "scanner": scanner, "status": status, "coverage_status": "complete",
                "dependency_files": ["requirements.txt"], "ecosystems": ["pypi"],
                "inventory_available": True, "dependency_coverage": coverage,
            }],
        },
    }


def finding(package="flask", version="1.1.2", title="PYSEC-2023-62", ids=None):
    return {
        "title": title,
        "affected_component": package,
        "installed_version": version,
        "advisory_ids": ids or [title],
        "dependency_direct": True,
        "dependency_source": "requirements.txt",
    }


class TestFixVerification(unittest.TestCase):

    def test_resolved_finding_matches_package_and_advisory_aliases(self):
        previous = report("C:/project", [finding(ids=["PYSEC-2023-62", "CVE-2023-30861"])])
        current = report("C:/project", [finding(version="2.2.5", ids=["GHSA-m2qf-hxjv-5gpq", "CVE-2023-30861"])])

        result = compare_reports(previous, current)

        self.assertEqual(result.status, "unresolved")
        self.assertEqual(len(result.remaining), 1)
        self.assertEqual(
            result.remaining[0]["current"]["installed_version"],
            "2.2.5",
        )

    def test_missing_finding_is_resolved_only_with_matching_scope(self):
        previous = report("C:/project", [finding()])
        current = report("C:/project", [])

        result = compare_reports(previous, current)

        self.assertEqual(result.status, "resolved")
        self.assertEqual(len(result.resolved), 1)

    def test_new_findings_are_reported_separately(self):
        previous = report("C:/project", [finding()])
        current = report("C:/project", [finding(), finding(title="CVE-2026-1234")])

        result = compare_reports(previous, current)

        self.assertEqual(result.status, "unresolved_with_new_findings")
        self.assertEqual(len(result.remaining), 1)
        self.assertEqual(len(result.new), 1)

    def test_failed_scanner_never_marks_previous_finding_resolved(self):
        previous = report("C:/project", [finding()])
        current = report("C:/project", [], status="failed")

        result = compare_reports(previous, current)

        self.assertEqual(result.status, "inconclusive")
        self.assertEqual(result.resolved, [])
        self.assertEqual(result.remaining[0]["canonical_id"], "PYSEC-2023-62")
        self.assertEqual(result.remaining[0]["title"], "PYSEC-2023-62")
        self.assertTrue(result.warnings)

    def test_different_target_is_inconclusive(self):
        previous = report("C:/project-a", [finding()])
        current = report("C:/project-b", [])

        result = compare_reports(previous, current)

        self.assertEqual(result.status, "inconclusive")
        self.assertEqual(result.scope_status, "mismatch")
        self.assertEqual(result.resolved, [])

    def test_missing_target_is_unknown_scope(self):
        previous = {"scans": [{"scanner": "pip-audit", "status": "success", "findings": [finding()]}]}
        current = report("C:/project", [])

        result = compare_reports(previous, current)

        self.assertEqual(result.status, "inconclusive")
        self.assertEqual(result.scope_status, "unknown")

    def test_legacy_reports_without_scope_are_not_full_verification(self):
        previous = {
            "target": "C:/project",
            "scans": [{"scanner": "pip-audit", "status": "success", "findings": [finding()]}],
        }
        current = report("C:/project", [])

        result = compare_reports(previous, current)

        self.assertEqual(result.status, "inconclusive")
        self.assertEqual(result.scope_status, "unknown")
        self.assertEqual(result.resolved, [])
        self.assertEqual(result.scoped_verification["status"], "inconclusive")

    def test_matching_partial_direct_scope_reports_scoped_and_overall_results(self):
        previous = report("C:/project", [
            finding(package=f"pkg-{index}", title=f"CVE-2026-{1000 + index}")
            for index in range(12)
        ])
        current = report("C:/project", [
            finding(package=f"pkg-{index}", version="2.0.0", title=f"CVE-2026-{1000 + index}")
            for index in range(12)
        ])
        for item in (previous, current):
            item["scan_scope"]["coverage_status"] = "incomplete"
            item["scan_scope"]["scanners"][0]["coverage_status"] = "incomplete"
            item["scans"][0]["scope"]["coverage_status"] = "incomplete"
            item["scans"][0]["scope"]["dependency_coverage"]["transitive_dependencies"].update({
                "status": "incomplete", "scanned_count": 0,
            })
            item["scan_scope"]["scanners"][0]["dependency_coverage"]["transitive_dependencies"].update({
                "status": "incomplete", "scanned_count": 0,
            })

        result = compare_reports(previous, current)

        self.assertEqual(result.status, "inconclusive")
        self.assertEqual(result.resolved, [])
        scoped = result.scoped_verification
        self.assertEqual(scoped["scope_status"], "matched")
        self.assertEqual(scoped["status"], "unresolved")
        self.assertEqual(scoped["previous_findings"], 12)
        self.assertEqual(scoped["current_findings"], 12)
        self.assertEqual(len(scoped["remaining"]), 12)
        self.assertEqual(scoped["resolved"], [])

    def test_partial_direct_scope_can_resolve_findings_without_claiming_project_is_clean(self):
        previous = report("C:/project", [finding()])
        current = report("C:/project", [])
        for item in (previous, current):
            item["scan_scope"]["coverage_status"] = "incomplete"
            item["scan_scope"]["scanners"][0]["coverage_status"] = "incomplete"
            item["scans"][0]["scope"]["coverage_status"] = "incomplete"
            for coverage in (
                item["scans"][0]["scope"]["dependency_coverage"],
                item["scan_scope"]["scanners"][0]["dependency_coverage"],
            ):
                coverage["transitive_dependencies"]["status"] = "incomplete"

        result = compare_reports(previous, current)

        self.assertEqual(result.status, "inconclusive")
        self.assertEqual(result.resolved, [])
        self.assertEqual(result.scoped_verification["status"], "resolved")
        self.assertEqual(len(result.scoped_verification["resolved"]), 1)
        self.assertTrue(any("overall project coverage remains incomplete" in warning
                            for warning in result.scoped_verification["warnings"]))

    def test_changed_direct_package_set_blocks_scoped_resolution(self):
        previous = report("C:/project", [finding(package="flask")])
        current = report("C:/project", [], status="success")
        current["scans"][0]["dependencies"] = [{
            "name": "werkzeug", "version": "3.1.9", "direct": True,
            "source_file": "requirements.txt",
        }]
        current["scan_scope"]["scanners"][0]["dependency_coverage"]["manifests"][0].update({
            "direct_dependencies_declared": 1, "direct_dependencies_scanned": 1,
        })
        current["scans"][0]["scope"]["dependency_coverage"]["manifests"][0].update({
            "direct_dependencies_declared": 1, "direct_dependencies_scanned": 1,
        })
        for item in (previous, current):
            item["scan_scope"]["coverage_status"] = "incomplete"
            item["scan_scope"]["scanners"][0]["coverage_status"] = "incomplete"
            item["scans"][0]["scope"]["coverage_status"] = "incomplete"
            for coverage in (
                item["scans"][0]["scope"]["dependency_coverage"],
                item["scan_scope"]["scanners"][0]["dependency_coverage"],
            ):
                coverage["transitive_dependencies"]["status"] = "incomplete"

        result = compare_reports(previous, current)

        self.assertEqual(result.status, "inconclusive")
        self.assertEqual(result.scoped_verification["status"], "inconclusive")

    def test_scanner_set_change_is_inconclusive(self):
        previous = report("C:/project", [finding()], scanner="pip-audit")
        current = report("C:/project", [], scanner="other-scanner")

        result = compare_reports(previous, current)

        self.assertEqual(result.status, "inconclusive")
        self.assertEqual(result.resolved, [])

    def test_modern_reports_with_incomplete_scope_are_inconclusive(self):
        previous = report("C:/project", [finding()])
        current = report("C:/project", [])
        for item in (previous, current):
            item["scan_scope"] = {
                "coverage_status": "incomplete",
                "dependency_files": ["requirements.txt"],
                "ecosystems": ["pypi"],
                "scanners": [{
                    "scanner": "pip-audit",
                    "status": "success",
                    "coverage_status": "incomplete",
                    "dependency_files": ["requirements.txt"],
                    "ecosystems": ["pypi"],
                    "inventory_available": False,
                }],
            }

        result = compare_reports(previous, current)

        self.assertEqual(result.status, "inconclusive")
        self.assertEqual(result.resolved, [])
        self.assertTrue(any("complete scan coverage" in warning for warning in result.warnings))

    def test_alias_match_does_not_leak_internal_metadata(self):
        previous = report("C:/project", [finding(ids=["CVE-2023-30861"])])
        current = report("C:/project", [finding(version="2.2.5", ids=["GHSA-m2qf-hxjv-5gpq"])])

        result = compare_reports(previous, current)

        self.assertEqual(result.status, "unresolved")
        self.assertNotIn("_scanner", result.remaining[0]["current"])

    def test_duplicate_alias_records_are_counted_as_one_finding(self):
        previous = report("C:/project", [
            finding(title="PYSEC-2023-62", ids=["PYSEC-2023-62", "CVE-2023-30861"]),
            finding(title="GHSA-m2qf-hxjv-5gpq", ids=["CVE-2023-30861", "GHSA-m2qf-hxjv-5gpq"]),
        ])
        current = report("C:/project", [
            finding(version="2.2.5", title="CVE-2023-30861", ids=["CVE-2023-30861"]),
        ])

        result = compare_reports(previous, current)

        self.assertEqual(result.previous_findings, 1)
        self.assertEqual(result.current_findings, 1)
        self.assertEqual(result.status, "unresolved")
        self.assertEqual(len(result.remaining), 1)
        self.assertEqual(result.resolved, [])

    def test_cvss_change_does_not_split_the_same_advisory_finding(self):
        old = finding(ids=["CVE-2026-1234"])
        old.update({"severity": "HIGH", "cvss_score": 8.1, "cvss_version": "3.1"})
        new = finding(version="2.0.0", ids=["CVE-2026-1234"])
        new.update({"severity": "CRITICAL", "cvss_score": 9.8, "cvss_version": "4.0"})

        result = compare_reports(report("C:/project", [old]), report("C:/project", [new]))

        self.assertEqual(result.status, "unresolved")
        self.assertEqual(len(result.remaining), 1)
        self.assertEqual(result.resolved, [])
        self.assertEqual(result.remaining[0]["current"]["cvss_score"], 9.8)

    def test_changed_dependency_manifest_scope_is_inconclusive(self):
        previous = report("C:/project", [finding()])
        current = report("C:/project", [])
        previous["scan_scope"] = {
            "coverage_status": "complete",
            "dependency_files": ["requirements.txt"],
            "ecosystems": ["pypi"],
            "scanners": [],
        }
        current["scan_scope"] = {
            "coverage_status": "complete",
            "dependency_files": ["pyproject.toml"],
            "ecosystems": ["pypi"],
            "scanners": [],
        }

        result = compare_reports(previous, current)

        self.assertEqual(result.status, "inconclusive")
        self.assertEqual(result.scope_status, "mismatch")
        self.assertEqual(result.resolved, [])


if __name__ == "__main__":
    unittest.main()
