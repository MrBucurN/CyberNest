import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from cybernest.fixes.candidate_audit import PipAuditCandidateAuditor


class TestPipAuditCandidateAuditor(unittest.TestCase):
    @staticmethod
    def output(version="3.1.9", vulnerabilities=None, name="Werkzeug"):
        return json.dumps({
            "dependencies": [{
                "name": name,
                "version": version,
                "vulns": vulnerabilities or [],
            }]
        })

    def test_accepts_exact_candidate_report_with_no_findings(self):
        result = SimpleNamespace(returncode=0, stdout=self.output(), stderr="")
        observed = {}

        def run(command, **kwargs):
            observed["command"] = command
            observed["timeout"] = kwargs["timeout"]
            observed["env"] = kwargs["env"]
            requirements_path = command[command.index("--requirement") + 1]
            with open(requirements_path, encoding="utf-8") as requirement_file:
                observed["requirements"] = requirement_file.read()
            return result

        with patch("cybernest.fixes.candidate_audit.subprocess.run", side_effect=run) as run_mock:
            audit = PipAuditCandidateAuditor().audit("Werkzeug", "3.1.9")

        self.assertEqual(audit.status, "verified")
        self.assertEqual(audit.advisories, [])
        self.assertIn("--no-deps", observed["command"])
        self.assertIn("--disable-pip", observed["command"])
        self.assertIn("--format", observed["command"])
        self.assertEqual(observed["timeout"], 20)
        self.assertEqual(observed["env"]["PIP_ONLY_BINARY"], ":all:")
        self.assertEqual(observed["requirements"], "Werkzeug==3.1.9\n")
        run_mock.assert_called_once()

    def test_accepts_candidate_report_containing_vulnerabilities(self):
        vulnerability = {"id": "PYSEC-2026-4312", "aliases": ["CVE-2026-12345"]}
        result = SimpleNamespace(
            returncode=1, stdout=self.output(vulnerabilities=[vulnerability]), stderr=""
        )

        with patch("cybernest.fixes.candidate_audit.subprocess.run", return_value=result):
            audit = PipAuditCandidateAuditor().audit("Werkzeug", "3.1.9")

        self.assertEqual(audit.status, "verified")
        self.assertEqual(audit.advisories, [vulnerability])

    def test_rejects_report_that_did_not_resolve_the_exact_candidate(self):
        result = SimpleNamespace(returncode=0, stdout=self.output("3.1.8"), stderr="")

        with patch("cybernest.fixes.candidate_audit.subprocess.run", return_value=result):
            audit = PipAuditCandidateAuditor().audit("Werkzeug", "3.1.9")

        self.assertEqual(audit.status, "invalid_report")
        self.assertIn("requested candidate version", audit.error)

    def test_non_audit_process_failure_is_not_a_clean_candidate(self):
        result = SimpleNamespace(returncode=2, stdout="", stderr="network unavailable")

        with patch("cybernest.fixes.candidate_audit.subprocess.run", return_value=result):
            audit = PipAuditCandidateAuditor().audit("Werkzeug", "3.1.9")

        self.assertEqual(audit.status, "audit_error")
        self.assertIn("network unavailable", audit.error)

    def test_invalid_version_does_not_invoke_pip_audit(self):
        with patch("cybernest.fixes.candidate_audit.subprocess.run") as run:
            audit = PipAuditCandidateAuditor().audit("Werkzeug", "not-a-version")

        self.assertEqual(audit.status, "invalid_version")
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
