
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cybernest.integrations.pip_audit import PipAuditScanner
from cybernest.integrations.advisory_severity import AdvisorySeverityResolver, SeverityInfo
from cybernest.project_discovery import ProjectDiscovery
from cybernest.scan_result import ScanStatus


class TestPipAuditScanner(unittest.TestCase):

    def test_scan_rejects_a_non_directory_target(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "missing"

            with self.assertRaises(NotADirectoryError):
                PipAuditScanner().scan(target)

    def test_scan_returns_no_findings_without_requirements_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            findings = PipAuditScanner().scan(Path(temp_dir))

        self.assertEqual(findings, [])

    @patch("cybernest.integrations.pip_audit.subprocess.run")
    def test_scan_maps_vulnerabilities_to_findings(self, mock_run):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir)
            (target / "requirements.txt").write_text(
                "example-package==1.0\n"
            )

            mock_run.return_value.returncode = 1
            mock_run.return_value.stderr = ""
            mock_run.return_value.stdout = json.dumps({
                "dependencies": [
                    {
                        "name": "example-package",
                        "version": "1.0",
                        "vulns": [
                            {
                                "id": "TEST-2026-001",
                                "description": "Example advisory",
                                "fix_versions": ["1.1"],
                                "link": "https://example.com/advisory",
                            },
                            {
                                "id": "TEST-2026-001",
                                "description": "Duplicate advisory",
                                "fix_versions": ["1.1"],
                                "link": "https://example.com/advisory",
                            },
                        ],
                    }
                ]
            })

            findings = PipAuditScanner().scan(target)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "TEST-2026-001")
        self.assertEqual(
            findings[0].affected_component,
            "example-package"
        )
        self.assertEqual(findings[0].installed_version, "1.0")
        self.assertEqual(findings[0].fixed_version, "1.1")

    def test_scan_with_status_skips_missing_requirements(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = PipAuditScanner().scan_with_status(
                Path(temp_dir)
            )

        self.assertEqual(result.status, ScanStatus.SKIPPED)
        self.assertEqual(result.scanner, "pip-audit")
        self.assertEqual(result.findings, [])
        self.assertIn("requirements", result.message)

    @patch("cybernest.integrations.pip_audit.subprocess.run")
    def test_scan_supports_pep621_project_and_optional_dependencies(self, mock_run):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir)
            (target / "pyproject.toml").write_text(
                """[project]
name = "demo"
version = "1.0"
requires-python = "==3.14.10"
dependencies = ["Flask>=2"]

[project.optional-dependencies]
dev = ["pytest>=8"]
""",
                encoding="utf-8",
            )
            mock_run.side_effect = [
                type("Completed", (), {
                    "returncode": 0,
                    "stderr": "",
                    "stdout": json.dumps({"dependencies": [{
                        "name": "Flask", "version": "3.1.0", "vulns": [],
                    }]}),
                })(),
                type("Completed", (), {
                    "returncode": 0,
                    "stderr": "",
                    "stdout": json.dumps({"dependencies": [
                        {"name": "Flask", "version": "3.1.0", "vulns": []},
                        {"name": "pytest", "version": "8.0.0", "vulns": []},
                    ]}),
                })(),
            ]

            result = PipAuditScanner().scan_with_status(target)

        self.assertEqual(result.status, ScanStatus.SUCCESS)
        self.assertEqual(result.scope["coverage_status"], "complete")
        self.assertEqual(result.scope["supported_formats"], ["pyproject"])
        self.assertEqual(len(mock_run.call_args_list), 2)
        self.assertTrue(all(call.kwargs["cwd"] == target for call in mock_run.call_args_list))
        self.assertEqual({item["name"] for item in result.dependencies}, {"Flask", "pytest"})
        self.assertEqual({item["source_file"] for item in result.dependencies}, {
            "pyproject.toml", "pyproject.toml[extra:dev]",
        })

    @patch("cybernest.integrations.pip_audit.subprocess.run")
    def test_unsupported_lockfile_is_reported_as_incomplete_without_a_clean_result(self, mock_run):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir)
            (target / "poetry.lock").write_text("", encoding="utf-8")

            result = PipAuditScanner().scan_with_status(target)

        mock_run.assert_not_called()
        self.assertEqual(result.status, ScanStatus.SKIPPED)
        self.assertEqual(result.scope["coverage_status"], "incomplete")
        self.assertIn("poetry.lock", result.scope["unsupported_files"])

    @patch("cybernest.integrations.pip_audit.subprocess.run")
    def test_exact_pins_fall_back_to_direct_only_when_transitive_resolution_fails(self, mock_run):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir)
            (target / "requirements.txt").write_text("example-package==1.0\n")
            mock_run.side_effect = [
                type("Completed", (), {
                    "returncode": 1,
                    "stderr": "Could not resolve https://user:password@example.invalid/pkg",
                    "stdout": "",
                })(),
                type("Completed", (), {
                    "returncode": 0,
                    "stderr": "",
                    "stdout": json.dumps({"dependencies": [{
                        "name": "example-package", "version": "1.0", "vulns": [],
                    }]}),
                })(),
            ]

            result = PipAuditScanner().scan_with_status(target)

        self.assertEqual(result.status, ScanStatus.SUCCESS)
        self.assertEqual(result.scope["coverage_status"], "incomplete")
        self.assertEqual(len(mock_run.call_args_list), 2)
        self.assertIn("--no-deps", mock_run.call_args_list[1].args[0])
        self.assertIn("--disable-pip", mock_run.call_args_list[1].args[0])
        self.assertEqual(mock_run.call_args_list[0].kwargs["env"]["PIP_ONLY_BINARY"], ":all:")
        warning = " ".join(result.scope["warnings"])
        self.assertIn("only exact-pinned direct dependencies", warning.casefold())
        self.assertIn("could not be reached", warning)
        self.assertEqual(
            result.scope["dependency_coverage"]["manifests"][0]["resolution_failure"]["classification"],
            "network_error",
        )
        self.assertNotIn("password", warning)

    @patch("cybernest.integrations.pip_audit.probe_pypi_release", return_value={
        "status": "available",
        "release_exists": True,
        "python_compatible": True,
        "target_wheel_available": False,
        "source_archive_available": True,
        "source": "PyPI JSON API",
    })
    @patch("cybernest.integrations.pip_audit.subprocess.run")
    def test_partial_coverage_explains_transitive_wheel_gap(self, mock_run, mock_probe):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir)
            (target / "requirements.txt").write_text(
                "Flask==1.1.2\nWerkzeug==1.0.1\nMarkupSafe==2.0.1\n"
            )
            mock_run.side_effect = [
                type("Completed", (), {
                    "returncode": 1,
                    "stderr": "ERROR: No matching distribution found for markupsafe==2.0.1",
                    "stdout": "",
                })(),
                type("Completed", (), {
                    "returncode": 0,
                    "stderr": "",
                    "stdout": json.dumps({"dependencies": [
                        {"name": "Flask", "version": "1.1.2", "vulns": []},
                        {"name": "Werkzeug", "version": "1.0.1", "vulns": []},
                        {"name": "MarkupSafe", "version": "2.0.1", "vulns": []},
                    ]}),
                })(),
            ]

            result = PipAuditScanner().scan_with_status(target)

        mock_probe.assert_called_once()
        self.assertEqual(result.scope["coverage_status"], "incomplete")
        manifest = result.scope["dependency_coverage"]["manifests"][0]
        self.assertEqual(manifest["status"], "partial")
        self.assertIn("markupsafe==2.0.1", manifest["reason"])
        self.assertIn("source builds are disabled", manifest["reason"])
        self.assertEqual(manifest["resolution_failure"]["classification"], "no_compatible_wheel")
        self.assertFalse(manifest["resolution_failure"]["target_wheel_available"])
        self.assertTrue(manifest["resolution_failure"]["source_archive_available"])

    @patch("cybernest.integrations.pip_audit.subprocess.run")
    def test_scan_with_status_success(self, mock_run):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir)
            (target / "requirements.txt").write_text(
                "example-package==1.0\n"
            )

            mock_run.return_value.returncode = 0
            mock_run.return_value.stderr = ""
            mock_run.return_value.stdout = json.dumps({
                "dependencies": [
                    {
                        "name": "example-package",
                        "version": "1.0",
                        "vulns": [],
                    }
                ],
                "fixes": [],
            })

            result = PipAuditScanner().scan_with_status(target)

        self.assertEqual(result.status, ScanStatus.SUCCESS)
        self.assertEqual(result.scanner, "pip-audit")
        self.assertEqual(result.findings, [])
        self.assertEqual(result.dependencies, [{
            "name": "example-package",
            "version": "1.0",
            "resolved_version": "1.0",
            "direct": True,
            "source_file": "requirements.txt",
            "declared_specifier": "==1.0",
        }])
        self.assertEqual(result.scope["coverage_status"], "complete")
        self.assertEqual(result.scope["dependency_files"], ["requirements.txt"])
        self.assertEqual(result.scope["ecosystems"], ["pypi"])
        self.assertEqual(result.scope["scanner_execution_status"], "success")
        self.assertEqual(result.scope["security_scan_coverage"], "complete")
        self.assertEqual(result.scope["dependency_coverage"]["direct_dependencies"]["declared_count"], 1)
        self.assertEqual(result.scope["dependency_coverage"]["direct_dependencies"]["scanned_count"], 1)
        self.assertEqual(result.scope["dependency_coverage"]["transitive_dependencies"]["status"], "not_applicable")

    @patch("cybernest.integrations.pip_audit.subprocess.run")
    def test_declared_direct_dependency_missing_from_inventory_is_not_reported_clean(self, mock_run):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir)
            (target / "requirements.txt").write_text("example-package==1.0\n")
            mock_run.return_value.returncode = 0
            mock_run.return_value.stderr = ""
            mock_run.return_value.stdout = json.dumps({"dependencies": []})

            result = PipAuditScanner().scan_with_status(target)

        self.assertEqual(result.status, ScanStatus.SUCCESS)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.scope["coverage_status"], "incomplete")
        direct = result.scope["dependency_coverage"]["direct_dependencies"]
        self.assertEqual(direct["declared_count"], 1)
        self.assertEqual(direct["scanned_count"], 0)
        self.assertEqual(direct["unscanned_count"], 1)

    @patch("cybernest.integrations.pip_audit.subprocess.run")
    def test_environment_marker_excluded_dependency_is_reported_as_not_applicable(self, mock_run):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir)
            (target / "requirements.txt").write_text(
                'example-package==1.0; python_version < "3.0"\n'
            )
            mock_run.return_value.returncode = 0
            mock_run.return_value.stderr = ""
            mock_run.return_value.stdout = json.dumps({"dependencies": []})

            result = PipAuditScanner().scan_with_status(target)

        self.assertEqual(result.scope["coverage_status"], "complete")
        direct = result.scope["dependency_coverage"]["direct_dependencies"]
        self.assertEqual(direct["declared_count"], 1)
        self.assertEqual(direct["scanned_count"], 0)
        self.assertEqual(direct["not_applicable_count"], 1)
        self.assertEqual(direct["unscanned_count"], 0)

    @patch("cybernest.integrations.pip_audit.subprocess.run")
    def test_scan_with_status_handles_failure(self, mock_run):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir)
            (target / "requirements.txt").write_text(
                "example-package==1.0\n"
            )

            mock_run.return_value.returncode = 2
            mock_run.return_value.stderr = "Scanner error"
            mock_run.return_value.stdout = ""

            result = PipAuditScanner().scan_with_status(target)

        self.assertEqual(result.status, ScanStatus.FAILED)
        self.assertEqual(result.scanner, "pip-audit")
        self.assertEqual(result.findings, [])
        self.assertIn("Scanner error", result.message)
        self.assertEqual(result.scope["dependency_files"], ["requirements.txt"])
        self.assertEqual(result.scope["coverage_status"], "incomplete")

    def test_python_minor_target_matches_a_patch_level_runtime(self):
        scanner = PipAuditScanner(python_target_override="3.14")
        with tempfile.TemporaryDirectory() as temp_dir:
            discovery = ProjectDiscovery(root=Path(temp_dir))

            scanner._apply_scan_python_context(discovery)
            scope = scanner._scope(
                status=ScanStatus.SUCCESS,
                inventory_available=True,
                discovery=discovery,
            )

        self.assertEqual(scope["python_scan_status"], "runtime_context")
        self.assertFalse(any("cross-target" in warning for warning in discovery.warnings))

    @patch.object(
        AdvisorySeverityResolver,
        "resolve",
        return_value=SeverityInfo(lookup_status="network_error"),
    )
    @patch("cybernest.integrations.pip_audit.subprocess.run")
    def test_scan_continues_when_severity_api_is_unavailable(
        self,
        mock_run,
        _mock_resolve,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir)
            (target / "requirements.txt").write_text("example-package==1.0\n")
            mock_run.return_value.returncode = 1
            mock_run.return_value.stderr = ""
            mock_run.return_value.stdout = json.dumps({
                "dependencies": [{
                    "name": "example-package",
                    "version": "1.0",
                    "vulns": [{"id": "CVE-2026-1234", "aliases": []}],
                }],
            })

            result = PipAuditScanner().scan_with_status(target)

        self.assertEqual(result.status, ScanStatus.SUCCESS)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].severity, "UNKNOWN")
        self.assertEqual(
            result.findings[0].severity_lookup_status,
            "network_error",
        )


if __name__ == "__main__":
    unittest.main()
