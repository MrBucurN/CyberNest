import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cybernest.engine import ScanEngine
from cybernest.fixes.verification import compare_reports
from cybernest.integrations.advisory_severity import AdvisorySeverityResolver, SeverityInfo
from cybernest.integrations.pip_audit import PipAuditScanner
from cybernest.reports.json_report import build_report


class TestPipAuditRescanVerificationIntegration(unittest.TestCase):
    def test_temporary_project_rescan_reports_resolved_remaining_and_new(self):
        with tempfile.TemporaryDirectory(prefix="cybernest-rescan-") as directory:
            target = Path(directory)

            def scan(version, vulnerabilities):
                (target / "requirements.txt").write_text(
                    f"Flask=={version}\n", encoding="utf-8"
                )
                payload = {"dependencies": [{
                    "name": "flask",
                    "version": version,
                    "vulns": vulnerabilities,
                }]}
                completed = type("Completed", (), {
                    "returncode": 1 if vulnerabilities else 0,
                    "stdout": json.dumps(payload),
                    "stderr": "",
                })()
                engine = ScanEngine()
                engine.register(PipAuditScanner())
                with patch("cybernest.integrations.pip_audit.subprocess.run", return_value=completed):
                    with patch.object(
                        AdvisorySeverityResolver,
                        "resolve",
                        return_value=SeverityInfo(lookup_status="not_available"),
                    ):
                        engine.scan(target)
                return build_report(engine.results, target=target)

            initial = scan("1.1.2", [
                {"id": "PYSEC-2023-62", "aliases": ["CVE-2023-30861", "GHSA-m2qf-hxjv-5gpq"]},
                {"id": "CVE-2026-1234", "aliases": []},
            ])
            updated = scan("2.2.5", [
                {"id": "CVE-2026-1234", "aliases": []},
                {"id": "CVE-2026-5678", "aliases": []},
            ])
            clean = scan("3.1.3", [])

            partial = compare_reports(initial, updated)
            resolved = compare_reports(initial, clean)

        self.assertEqual(partial.status, "partially_resolved")
        self.assertEqual(len(partial.resolved), 1)
        self.assertEqual(len(partial.remaining), 1)
        self.assertEqual(len(partial.new), 1)
        self.assertEqual(resolved.status, "resolved")
        self.assertEqual(len(resolved.resolved), 2)


if __name__ == "__main__":
    unittest.main()
