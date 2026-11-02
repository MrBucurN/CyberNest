
import unittest

from cybernest.finding import Finding


class TestFinding(unittest.TestCase):

    def test_finding_stores_values(self):
        finding = Finding(
            title="Example vulnerability",
            severity="HIGH",
            tool="pip-audit",
            category="dependency",
        )

        self.assertEqual(finding.title, "Example vulnerability")
        self.assertEqual(finding.severity, "HIGH")
        self.assertEqual(finding.tool, "pip-audit")
        self.assertEqual(finding.category, "dependency")

    def test_optional_fields_default_to_empty(self):
        finding = Finding(
            title="Example",
            severity="LOW",
            tool="Trivy",
            category="dependency",
        )

        self.assertEqual(finding.description, "")
        self.assertEqual(finding.fixed_version, "")

    def test_additional_fields_have_independent_default_lists(self):
        first = Finding(
            title="Example one",
            severity="LOW",
            tool="Trivy",
            category="dependency",
        )
        second = Finding(
            title="Example two",
            severity="LOW",
            tool="Trivy",
            category="dependency",
        )

        first.additional_descriptions.append("Additional description")
        first.additional_fix_versions.append("2.0.0")

        self.assertEqual(second.additional_descriptions, [])
        self.assertEqual(second.additional_fix_versions, [])


if __name__ == "__main__":
    unittest.main()
