import unittest

from cybernest.deduplication import deduplicate_findings
from cybernest.finding import Finding


class TestDeduplicateFindings(unittest.TestCase):

    def test_removes_duplicate_findings(self):
        findings = [
            Finding(
                title="PYSEC-2023-62",
                severity="HIGH",
                tool="pip-audit",
                category="dependency",
                affected_component="flask",
                installed_version="1.1.2",
                description="Original description",
            ),
            Finding(
                title="PYSEC-2023-62",
                severity="HIGH",
                tool="pip-audit",
                category="dependency",
                affected_component="flask",
                installed_version="1.1.2",
                description="Duplicate description",
            ),
            Finding(
                title="PYSEC-2023-62",
                severity="HIGH",
                tool="pip-audit",
                category="dependency",
                affected_component="flask",
                installed_version="1.1.2",
            ),
        ]

        unique_findings = deduplicate_findings(findings)

        self.assertEqual(len(unique_findings), 1)
        self.assertIsNot(unique_findings[0], findings[0])
        self.assertEqual(
            unique_findings[0].additional_descriptions,
            ["Duplicate description"],
        )
        self.assertEqual(findings[0].additional_descriptions, [])
        self.assertEqual(findings[1].additional_descriptions, [])

    def test_does_not_duplicate_additional_descriptions(self):
        findings = [
            Finding(
                title="PYSEC-2023-62",
                severity="HIGH",
                tool="pip-audit",
                category="dependency",
                affected_component="flask",
                installed_version="1.1.2",
                description="Original description",
            ),
            Finding(
                title="PYSEC-2023-62",
                severity="HIGH",
                tool="pip-audit",
                category="dependency",
                affected_component="flask",
                installed_version="1.1.2",
                description="Additional description",
            ),
            Finding(
                title="PYSEC-2023-62",
                severity="HIGH",
                tool="pip-audit",
                category="dependency",
                affected_component="flask",
                installed_version="1.1.2",
                description="Additional description",
            ),
        ]

        unique_findings = deduplicate_findings(findings)

        self.assertEqual(
            unique_findings[0].additional_descriptions,
            ["Additional description"],
        )

    def test_uses_first_nonempty_description_as_main_description(self):
        findings = [
            Finding(
                title="PYSEC-2023-62",
                severity="HIGH",
                tool="pip-audit",
                category="dependency",
                affected_component="flask",
                installed_version="1.1.2",
            ),
            Finding(
                title="PYSEC-2023-62",
                severity="HIGH",
                tool="pip-audit",
                category="dependency",
                affected_component="flask",
                installed_version="1.1.2",
                description="Important vulnerability",
            ),
        ]

        unique_findings = deduplicate_findings(findings)

        self.assertEqual(
            unique_findings[0].description,
            "Important vulnerability",
        )
        self.assertEqual(unique_findings[0].additional_descriptions, [])
        self.assertEqual(findings[0].description, "")

    def test_merges_incoming_additional_descriptions(self):
        findings = [
            Finding(
                title="PYSEC-2023-62",
                severity="HIGH",
                tool="pip-audit",
                category="dependency",
                affected_component="flask",
                installed_version="1.1.2",
                description="Primary description",
            ),
            Finding(
                title="PYSEC-2023-62",
                severity="HIGH",
                tool="pip-audit",
                category="dependency",
                affected_component="flask",
                installed_version="1.1.2",
                description="Incoming description",
                additional_descriptions=[
                    "Additional source detail",
                    "Primary description",
                    "Incoming description",
                ],
            ),
        ]

        unique_findings = deduplicate_findings(findings)

        self.assertEqual(
            unique_findings[0].description,
            "Primary description",
        )
        self.assertEqual(
            unique_findings[0].additional_descriptions,
            ["Incoming description", "Additional source detail"],
        )
        self.assertEqual(
            findings[1].additional_descriptions,
            [
                "Additional source detail",
                "Primary description",
                "Incoming description",
            ],
        )

    def test_normalizes_first_findings_additional_descriptions(self):
        finding = Finding(
            title="PYSEC-2023-62",
            severity="HIGH",
            tool="pip-audit",
            category="dependency",
            affected_component="flask",
            installed_version="1.1.2",
            description="Main description",
            additional_descriptions=[
                "Main description",
                "Extra detail",
                "Extra detail",
                "",
            ],
        )

        unique_findings = deduplicate_findings([finding])

        self.assertEqual(
            unique_findings[0].additional_descriptions,
            ["Extra detail"],
        )
        self.assertEqual(
            finding.additional_descriptions,
            [
                "Main description",
                "Extra detail",
                "Extra detail",
                "",
            ],
        )

    def test_merges_distinct_fix_versions_without_reordering(self):
        findings = [
            Finding(
                title="PYSEC-2023-62",
                severity="HIGH",
                tool="pip-audit",
                category="dependency",
                affected_component="flask",
                installed_version="1.1.2",
                fixed_version="2.2.5, 2.3.2",
                additional_fix_versions=["3.0.0"],
            ),
            Finding(
                title="PYSEC-2023-62",
                severity="HIGH",
                tool="pip-audit",
                category="dependency",
                affected_component="flask",
                installed_version="1.1.2",
                fixed_version="2.3.2, 3.1.3",
                additional_fix_versions=["3.2.0", "3.1.3"],
            ),
        ]

        unique_findings = deduplicate_findings(findings)

        self.assertEqual(len(unique_findings), 1)
        self.assertEqual(unique_findings[0].fixed_version, "2.2.5, 2.3.2")
        self.assertEqual(
            unique_findings[0].additional_fix_versions,
            ["3.0.0", "3.1.3", "3.2.0"],
        )
        self.assertEqual(findings[0].additional_fix_versions, ["3.0.0"])
        self.assertEqual(findings[1].additional_fix_versions, ["3.2.0", "3.1.3"])

    def test_promotes_first_incoming_fix_version_when_primary_is_empty(self):
        findings = [
            Finding(
                title="PYSEC-2023-62",
                severity="HIGH",
                tool="pip-audit",
                category="dependency",
                affected_component="flask",
                installed_version="1.1.2",
            ),
            Finding(
                title="PYSEC-2023-62",
                severity="HIGH",
                tool="pip-audit",
                category="dependency",
                affected_component="flask",
                installed_version="1.1.2",
                fixed_version="2.2.5, 2.3.2",
                additional_fix_versions=["2.3.2", "3.1.3"],
            ),
        ]

        unique_findings = deduplicate_findings(findings)

        self.assertEqual(unique_findings[0].fixed_version, "2.2.5")
        self.assertEqual(
            unique_findings[0].additional_fix_versions,
            ["2.3.2", "3.1.3"],
        )
        self.assertEqual(findings[0].fixed_version, "")
        self.assertEqual(findings[1].fixed_version, "2.2.5, 2.3.2")

    def test_preserves_same_vulnerability_in_different_packages(self):
        findings = [
            Finding(
                title="PYSEC-2023-62",
                severity="HIGH",
                tool="pip-audit",
                category="dependency",
                affected_component="flask",
                installed_version="1.1.2",
            ),
            Finding(
                title="PYSEC-2023-62",
                severity="HIGH",
                tool="pip-audit",
                category="dependency",
                affected_component="werkzeug",
                installed_version="1.1.2",
            ),
        ]

        unique_findings = deduplicate_findings(findings)

        self.assertEqual(len(unique_findings), 2)

    def test_returns_empty_list_for_empty_input(self):
        unique_findings = deduplicate_findings([])

        self.assertEqual(unique_findings, [])

    def test_preserves_findings_for_different_versions(self):
        findings = [
            Finding(
                title="PYSEC-2023-62",
                severity="HIGH",
                tool="pip-audit",
                category="dependency",
                affected_component="flask",
                installed_version="1.1.2",
            ),
            Finding(
                title="PYSEC-2023-62",
                severity="HIGH",
                tool="pip-audit",
                category="dependency",
                affected_component="flask",
                installed_version="2.0.0",
            ),
        ]

        unique_findings = deduplicate_findings(findings)

        self.assertEqual(len(unique_findings), 2)

    def test_promotes_cvss_metadata_from_duplicate_finding(self):
        findings = [
            Finding(
                title="CVE-2026-1234",
                severity="UNKNOWN",
                tool="pip-audit",
                category="dependency",
                affected_component="example",
                installed_version="1.0",
                severity_lookup_status="not_available",
            ),
            Finding(
                title="CVE-2026-1234",
                severity="HIGH",
                tool="pip-audit",
                category="dependency",
                affected_component="example",
                installed_version="1.0",
                cvss_score=8.1,
                cvss_vector="CVSS:3.1/example-vector",
                cvss_version="3.1",
                severity_source="NVD",
                severity_source_url="https://nvd.example/CVE-2026-1234",
                severity_lookup_status="resolved",
                reported_severity="HIGH",
            ),
        ]

        unique = deduplicate_findings(findings)

        self.assertEqual(len(unique), 1)
        merged = unique[0]
        self.assertEqual(merged.severity, "HIGH")
        self.assertEqual(merged.cvss_score, 8.1)
        self.assertEqual(merged.cvss_vector, "CVSS:3.1/example-vector")
        self.assertEqual(merged.cvss_version, "3.1")
        self.assertEqual(merged.severity_source, "NVD")
        self.assertEqual(merged.severity_source_url, "https://nvd.example/CVE-2026-1234")
        self.assertEqual(merged.severity_lookup_status, "resolved")
        self.assertEqual(merged.reported_severity, "HIGH")
        self.assertEqual(findings[0].severity, "UNKNOWN")
        self.assertIsNone(findings[0].cvss_score)

    def test_cvss_source_precedence_wins_over_newer_vector_version(self):
        findings = [
            Finding(
                title="CVE-2026-1234",
                severity="CRITICAL",
                tool="pip-audit",
                category="dependency",
                affected_component="example",
                installed_version="1.0",
                cvss_score=9.8,
                cvss_vector="CVSS:4.0/github-vector",
                cvss_version="4.0",
                severity_source="GitHub Advisory Database",
                severity_lookup_status="resolved",
            ),
            Finding(
                title="CVE-2026-1234",
                severity="MEDIUM",
                tool="pip-audit",
                category="dependency",
                affected_component="example",
                installed_version="1.0",
                cvss_score=6.5,
                cvss_vector="CVSS:3.1/nvd-vector",
                cvss_version="3.1",
                severity_source="NVD",
                severity_source_url="https://nvd.example/CVE-2026-1234",
                severity_lookup_status="resolved",
            ),
        ]

        merged = deduplicate_findings(findings)[0]

        self.assertEqual(merged.severity, "MEDIUM")
        self.assertEqual(merged.cvss_score, 6.5)
        self.assertEqual(merged.cvss_version, "3.1")
        self.assertEqual(merged.severity_source, "NVD")


if __name__ == "__main__":
    unittest.main()
