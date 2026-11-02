import tempfile
import unittest
from pathlib import Path

from cybernest.project_discovery import discover_project


class TestProjectDiscovery(unittest.TestCase):
    def test_requirements_includes_constraints_markers_and_extras_are_discovered(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text(
                "-r requirements/base.txt\n-c constraints.txt\n",
                encoding="utf-8",
            )
            (root / "requirements").mkdir()
            (root / "requirements" / "base.txt").write_text(
                "Flask[async]>=2.0; python_version >= '3.10'\n",
                encoding="utf-8",
            )
            (root / "constraints.txt").write_text("Werkzeug<4\n", encoding="utf-8")

            result = discover_project(root)

        manifest = next(item for item in result.manifests if item.path.name == "requirements.txt")
        self.assertFalse(manifest.unsupported_reason)
        self.assertEqual(manifest.direct_dependencies[0]["canonical_name"], "flask")
        self.assertEqual(manifest.direct_dependencies[0]["extras"], "async")
        self.assertIn("requirements/base.txt", manifest.included_files[0].as_posix())

    def test_include_escape_and_cycle_are_not_scanned(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "project"
            root.mkdir()
            (parent / "outside.txt").write_text("Flask==1.1.2\n", encoding="utf-8")
            (root / "requirements.txt").write_text("-r ../outside.txt\n", encoding="utf-8")
            escaped = discover_project(root)
            self.assertTrue(any("outside the project" in warning for warning in escaped.warnings))

            (root / "requirements.txt").write_text("-r requirements-dev.txt\n", encoding="utf-8")
            (root / "requirements-dev.txt").write_text("-r requirements.txt\n", encoding="utf-8")
            cycled = discover_project(root)
            self.assertTrue(any("cycle" in warning for warning in cycled.warnings))

    def test_pep621_main_and_optional_groups_are_separate_and_python_range_is_not_collapsed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text(
                """[project]
name = "demo"
version = "1.0"
requires-python = ">=3.10,<3.13"
dependencies = ["Flask>=2.0"]

[project.optional-dependencies]
dev = ["pytest>=8"]
""",
                encoding="utf-8",
            )

            result = discover_project(root)

        self.assertEqual({item.group for item in result.manifests}, {"main", "extra:dev"})
        self.assertEqual(result.requires_python, ">=3.10,<3.13")
        self.assertEqual(result.python_target, "")
        self.assertEqual(result.python_target_confidence, "range")

    def test_exact_python_metadata_and_python_version_file_are_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text(
                """[project]
name = "demo"
version = "1.0"
requires-python = "==3.11.8"
dependencies = []
""",
                encoding="utf-8",
            )
            result = discover_project(root)
            self.assertEqual(result.python_target, "3.11.8")
            self.assertEqual(result.python_target_source, "requires-python metadata")

            (root / ".python-version").write_text("3.12.1\n", encoding="utf-8")
            conflict = discover_project(root)

        self.assertEqual(conflict.python_target, "3.12.1")
        self.assertTrue(conflict.python_target_conflict)

    def test_poetry_lock_and_pyproject_are_explicitly_unsupported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text(
                "[tool.poetry]\nname='demo'\nversion='1.0'\n", encoding="utf-8"
            )
            (root / "poetry.lock").write_text("", encoding="utf-8")

            result = discover_project(root)

        self.assertFalse(result.manifests)
        self.assertEqual(set(result.unsupported_files), {"pyproject.toml", "poetry.lock"})
        self.assertFalse(result.coverage_complete)

    def test_setup_cfg_install_requires_is_supported_and_virtualenv_is_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "setup.cfg").write_text(
                "[options]\npython_requires = >=3.10\ninstall_requires =\n    Flask>=2\n",
                encoding="utf-8",
            )
            (root / ".venv").mkdir()
            (root / ".venv" / "requirements-hidden.txt").write_text("Flask==1\n", encoding="utf-8")

            result = discover_project(root)

        self.assertEqual(len(result.manifests), 1)
        self.assertEqual(result.manifests[0].format, "setup.cfg")
        self.assertEqual(result.manifests[0].direct_dependencies[0]["name"], "Flask")
        self.assertEqual(result.requires_python, ">=3.10")

    def test_requirements_in_is_discovered_and_multiversion_python_file_is_not_guessed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements-dev.in").write_text("pytest==8.0.0\n", encoding="utf-8")
            (root / ".python-version").write_text("3.11\n3.12\n", encoding="utf-8")

            result = discover_project(root)

        self.assertEqual(len(result.manifests), 1)
        self.assertEqual(result.manifests[0].path.name, "requirements-dev.in")
        self.assertEqual(result.manifests[0].direct_dependencies[0]["name"], "pytest")
        self.assertEqual(result.python_target, "")
        self.assertTrue(any("could not be parsed" in warning for warning in result.warnings))

    def test_unparsed_python_dependency_metadata_keeps_coverage_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text(
                '[project]\nname = "demo"\nversion = "1.0"\ndependencies = ["Flask>=2"]\n\n'
                '[dependency-groups]\ndev = ["pytest>=8"]\n',
                encoding="utf-8",
            )
            (root / "setup.py").write_text("from setuptools import setup\\n", encoding="utf-8")

            result = discover_project(root)

        self.assertEqual(len(result.manifests), 1)
        self.assertFalse(result.coverage_complete)
        self.assertIn("pyproject.toml", result.unsupported_files)
        self.assertIn("setup.py", result.unsupported_files)


if __name__ == "__main__":
    unittest.main()
