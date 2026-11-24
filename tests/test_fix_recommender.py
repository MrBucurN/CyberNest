import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from subprocess import TimeoutExpired
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError
from io import BytesIO

from cybernest.finding import Finding
from cybernest.fixes.candidate_audit import CandidateAuditResult
from cybernest.fixes.compatibility import CompatibilityAnalyzer
from cybernest.fixes.index_probe import inspect_release_payload
from cybernest.fixes.models import FixPlan, FixRecommendation
from cybernest.fixes.recommender import FixRecommender, PyPIClient, ReleaseMetadata
from cybernest.fixes.requirements import read_requirements


class FakePyPI:
    def __init__(self, releases=None, error=None):
        self.releases = releases or {}
        self.error = error
        self.calls = []

    def release(self, name, version, python_version):
        self.calls.append((name, version, python_version))
        if self.error:
            raise self.error
        release = self.releases.get(version)
        if release and release.target_wheel_available is None:
            return replace(release, target_wheel_available=release.wheel_available)
        return release


class FakeLatestPyPI(FakePyPI):
    def __init__(self, releases=None, latest=None):
        super().__init__(releases=releases)
        self.latest = list(latest or [])

    def latest_versions(self, name, limit=5):
        return self.latest[:limit]


class FakeCandidateAuditor:
    def __init__(self, results=None):
        self.results = results or {}
        self.calls = []

    def audit(self, name, version):
        self.calls.append((name, version))
        return self.results.get(
            version,
            CandidateAuditResult("audit_error", name, version, error="missing fixture"),
        )


class FakeCompatibility:
    def __init__(self, status="compatible"):
        self.status = status
        self.calls = 0

    def analyze(self, source, plan, python_version):
        self.calls += 1
        plan.dependency_resolution = "resolved"
        for recommendation in plan.recommendations:
            if recommendation.suggested_version:
                recommendation.compatibility_status = self.status


class TestFixRecommender(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.target = Path(self.temp.name)
        (self.target / "requirements.txt").write_text(
            "Flask==1.1.2\nWerkzeug==1.0.1\n", encoding="utf-8"
        )
        self.release = ReleaseMetadata(
            version="2.2.5", requires_python=">=3.8", wheel_available=True,
            python_compatible=True, yanked=False,
        )

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def finding(package, installed, advisory, fixes):
        return Finding(
            title=advisory,
            severity="HIGH",
            tool="pip-audit",
            category="dependency",
            affected_component=package,
            installed_version=installed,
            fixed_version=fixes,
        )

    def test_recommends_only_advisory_listed_stable_pypi_release(self):
        compatibility = FakeCompatibility()
        recommender = FixRecommender(
            pypi=FakePyPI({"2.2.5": self.release}), compatibility=compatibility
        )

        plan = recommender.build_plan(
            self.target,
            [self.finding("Flask", "1.1.2", "PYSEC-TEST-1", "2.2.5")],
            "3.14.0",
        )

        item = plan.recommendations[0]
        self.assertEqual(item.suggested_version, "2.2.5")
        self.assertEqual(item.recommendation_status, "recommended")
        self.assertEqual(item.compatibility_status, "compatible")
        self.assertEqual(plan.status, "ready_for_review")
        self.assertTrue(any("must be changed" in warning for warning in item.warnings))
        self.assertEqual(item.to_dict()["status"], "complete")
        self.assertEqual(item.unverified_advisories, [])

    def test_intersects_fix_candidates_to_cover_all_advisories(self):
        releases = {
            version: ReleaseMetadata(version, ">=3.8", True, True, False)
            for version in ("2.0.0", "2.1.0")
        }
        plan = FixRecommender(
            pypi=FakePyPI(releases), compatibility=FakeCompatibility()
        ).build_plan(
            self.target,
            [
                self.finding("Flask", "1.1.2", "CVE-2024-0001", "2.0.0, 2.1.0"),
                self.finding("flask", "1.1.2", "CVE-2024-0002", "2.1.0"),
            ],
            "3.14.0",
        )

        recommendation = plan.recommendations[0]
        self.assertEqual(recommendation.suggested_version, "2.1.0")
        self.assertEqual(len(recommendation.addressed_advisories), 2)
        self.assertEqual(recommendation.remaining_advisories, [])

    def test_partial_fix_is_reported_with_remaining_advisory(self):
        releases = {
            version: ReleaseMetadata(version, ">=3.8", True, True, False)
            for version in ("2.0.0", "2.1.0")
        }
        plan = FixRecommender(
            pypi=FakePyPI(releases), compatibility=FakeCompatibility()
        ).build_plan(
            self.target,
            [
                self.finding("Flask", "1.1.2", "CVE-2024-0001", "2.0.0"),
                self.finding("Flask", "1.1.2", "CVE-2024-0002", "2.1.0"),
            ],
            "3.14.0",
        )

        recommendation = plan.recommendations[0]
        self.assertEqual(recommendation.recommendation_status, "partial")
        self.assertEqual(len(recommendation.addressed_advisories), 1)
        self.assertEqual(len(recommendation.remaining_advisories), 1)
        self.assertEqual(plan.status, "partial")

    def test_advisory_without_fix_does_not_hide_a_partial_recommendation(self):
        plan = FixRecommender(
            pypi=FakePyPI({"2.0.0": self.release}),
            compatibility=FakeCompatibility(),
        ).build_plan(
            self.target,
            [
                self.finding("Flask", "1.1.2", "CVE-2024-0001", "2.0.0"),
                self.finding("Flask", "1.1.2", "CVE-2024-0002", ""),
            ],
            "3.14.0",
        )

        recommendation = plan.recommendations[0]
        self.assertEqual(recommendation.suggested_version, "2.0.0")
        self.assertEqual(recommendation.addressed_advisories, ["CVE-2024-0001"])
        self.assertEqual(recommendation.remaining_advisories, ["CVE-2024-0002"])
        self.assertEqual(recommendation.recommendation_status, "partial")

    def test_aliases_count_as_one_canonical_security_advisory(self):
        pysec = self.finding("Flask", "1.1.2", "PYSEC-2024-1", "2.2.5")
        pysec.advisory_ids = ["PYSEC-2024-1", "CVE-2024-0001"]
        ghsa = self.finding("flask", "1.1.2", "CVE-2024-0001", "2.2.5")
        ghsa.advisory_ids = ["CVE-2024-0001", "GHSA-abcd-1234-efgh"]

        plan = FixRecommender(
            pypi=FakePyPI({"2.2.5": self.release}),
            compatibility=FakeCompatibility(),
        ).build_plan(self.target, [pysec, ghsa], "3.14.0")

        recommendation = plan.recommendations[0]
        self.assertEqual(recommendation.affected_advisories, ["CVE-2024-0001"])
        self.assertEqual(recommendation.addressed_advisories, ["CVE-2024-0001"])
        self.assertEqual(
            recommendation.advisory_aliases["CVE-2024-0001"],
            ["GHSA-ABCD-1234-EFGH", "PYSEC-2024-1"],
        )
        self.assertEqual(recommendation.security_coverage_status, "complete")

    def test_no_known_fix_is_explicit(self):
        plan = FixRecommender(
            pypi=FakePyPI(), compatibility=FakeCompatibility()
        ).build_plan(
            self.target,
            [self.finding("Flask", "1.1.2", "PYSEC-TEST-1", "")],
            "3.14.0",
        )

        self.assertEqual(plan.recommendations[0].recommendation_status, "no_known_fix")
        self.assertIsNone(plan.recommendations[0].suggested_version)

    def test_unlisted_latest_candidate_is_recommended_only_after_exact_clean_audit(self):
        candidate_auditor = FakeCandidateAuditor({
            "3.1.9": CandidateAuditResult("verified", "Werkzeug", "3.1.9"),
        })
        pypi = FakeLatestPyPI(
            releases={
                "2.0.0": ReleaseMetadata("2.0.0", ">=3.8", True, True, False),
                "3.1.9": ReleaseMetadata("3.1.9", ">=3.8", True, True, False),
            },
            latest=["3.1.9"],
        )

        plan = FixRecommender(
            pypi=pypi,
            compatibility=FakeCompatibility(),
            candidate_auditor=candidate_auditor,
        ).build_plan(
            self.target,
            [self.finding("Werkzeug", "1.0.1", "CVE-2024-0001", "2.0.0")],
            "3.14.0",
        )

        recommendation = plan.recommendations[0]
        self.assertEqual(recommendation.suggested_version, "3.1.9")
        self.assertEqual(recommendation.candidate_audit_status, "verified")
        self.assertEqual(recommendation.candidate_audit_source, "pip-audit exact-pin audit")
        self.assertEqual(recommendation.security_coverage_status, "complete")
        self.assertEqual(recommendation.recommendation_status, "recommended")
        self.assertEqual(candidate_auditor.calls, [("Werkzeug", "3.1.9")])
        latest = next(
            item for item in recommendation.candidate_validations
            if item["version"] == "3.1.9"
        )
        self.assertEqual(latest["candidate_security_audit"]["status"], "verified")

    def test_latest_candidate_without_advisory_fix_needs_security_audit(self):
        candidate_auditor = FakeCandidateAuditor({
            "3.1.9": CandidateAuditResult("verified", "Werkzeug", "3.1.9"),
        })
        pypi = FakeLatestPyPI(
            releases={
                "3.1.9": ReleaseMetadata("3.1.9", ">=3.8", True, True, False),
            },
            latest=["3.1.9"],
        )

        plan = FixRecommender(
            pypi=pypi,
            compatibility=FakeCompatibility(),
            candidate_auditor=candidate_auditor,
        ).build_plan(
            self.target,
            [self.finding("Werkzeug", "1.0.1", "CVE-2024-0001", "")],
            "3.14.0",
        )

        recommendation = plan.recommendations[0]
        self.assertEqual(recommendation.suggested_version, "3.1.9")
        self.assertEqual(recommendation.security_coverage_status, "complete")
        self.assertEqual(recommendation.addressed_advisories, ["CVE-2024-0001"])
        self.assertEqual(recommendation.candidate_audit_status, "verified")

    def test_candidate_audit_preserves_remaining_and_new_advisories(self):
        candidate_auditor = FakeCandidateAuditor({
            "3.1.9": CandidateAuditResult(
                "verified", "Werkzeug", "3.1.9",
                advisories=[
                    {"id": "CVE-2024-0001", "aliases": ["GHSA-abcd-1234-efgh"]},
                    {"id": "CVE-2025-0002", "aliases": []},
                ],
            ),
        })
        pypi = FakeLatestPyPI(
            releases={
                "2.0.0": ReleaseMetadata("2.0.0", ">=3.8", True, True, False),
                "3.1.9": ReleaseMetadata("3.1.9", ">=3.8", True, True, False),
            },
            latest=["3.1.9"],
        )

        plan = FixRecommender(
            pypi=pypi,
            compatibility=FakeCompatibility(),
            candidate_auditor=candidate_auditor,
        ).build_plan(
            self.target,
            [self.finding("Werkzeug", "1.0.1", "CVE-2024-0001", "2.0.0")],
            "3.14.0",
        )

        recommendation = plan.recommendations[0]
        self.assertEqual(recommendation.remaining_advisories, ["CVE-2024-0001"])
        self.assertEqual(recommendation.new_advisories, ["CVE-2025-0002"])
        self.assertEqual(recommendation.security_coverage_status, "partial")
        self.assertIsNone(recommendation.suggested_version)
        self.assertEqual(recommendation.recommendation_status, "requires_manual_review")

    def test_latest_candidate_is_not_recommended_when_exact_audit_is_inconclusive(self):
        candidate_auditor = FakeCandidateAuditor()
        pypi = FakeLatestPyPI(
            releases={
                "3.1.9": ReleaseMetadata("3.1.9", ">=3.8", True, True, False),
            },
            latest=["3.1.9"],
        )

        plan = FixRecommender(
            pypi=pypi,
            compatibility=FakeCompatibility(),
            candidate_auditor=candidate_auditor,
        ).build_plan(
            self.target,
            [self.finding("Werkzeug", "1.0.1", "CVE-2024-0001", "")],
            "3.14.0",
        )

        recommendation = plan.recommendations[0]
        self.assertIsNone(recommendation.suggested_version)
        self.assertEqual(recommendation.recommendation_status, "requires_manual_review")
        self.assertEqual(recommendation.security_coverage_status, "unverified")
        self.assertEqual(recommendation.unverified_advisories, ["CVE-2024-0001"])

    def test_yanked_prerelease_and_python_incompatible_releases_are_not_suggested(self):
        releases = {
            "2.2.5": ReleaseMetadata("2.2.5", ">=3.8", True, True, True),
            "2.3.0rc1": ReleaseMetadata("2.3.0rc1", ">=3.8", True, True, False),
            "3.0.0": ReleaseMetadata("3.0.0", ">=3.15", True, False, False),
        }
        plan = FixRecommender(
            pypi=FakePyPI(releases), compatibility=FakeCompatibility()
        ).build_plan(
            self.target,
            [self.finding("Flask", "1.1.2", "PYSEC-TEST-1", "2.2.5, 2.3.0rc1, 3.0.0")],
            "3.14.0",
        )

        self.assertIsNone(plan.recommendations[0].suggested_version)
        self.assertEqual(plan.recommendations[0].recommendation_status, "requires_manual_review")
        self.assertEqual(plan.recommendations[0].status, "manual_review")
        self.assertTrue(any("yanked" in warning for warning in plan.recommendations[0].warnings))
        self.assertTrue(any("excludes" in warning for warning in plan.recommendations[0].warnings))

    def test_pypi_failure_produces_manual_review_without_guessing(self):
        plan = FixRecommender(
            pypi=FakePyPI(error=RuntimeError("offline")),
            compatibility=FakeCompatibility(),
        ).build_plan(
            self.target,
            [self.finding("Flask", "1.1.2", "PYSEC-TEST-1", "2.2.5")],
            "3.14.0",
        )

        recommendation = plan.recommendations[0]
        self.assertIsNone(recommendation.suggested_version)
        self.assertEqual(recommendation.recommendation_status, "requires_manual_review")
        self.assertTrue(any("offline" in warning for warning in recommendation.warnings))
        self.assertEqual(recommendation.to_dict()["status"], "unknown")
        self.assertEqual(recommendation.unverified_advisories, ["PYSEC-TEST-1"])

    def test_unknown_target_wheel_compatibility_is_not_recommended(self):
        class UnknownWheelPyPI(FakePyPI):
            def release(self, name, version, python_version):
                self.calls.append((name, version, python_version))
                return ReleaseMetadata(
                    version, ">=3.8", True, True, False,
                    target_wheel_available=None,
                )

        plan = FixRecommender(
            pypi=UnknownWheelPyPI(), compatibility=FakeCompatibility()
        ).build_plan(
            self.target,
            [self.finding("Flask", "1.1.2", "CVE-2024-0001", "2.2.5")],
            "3.14.0",
        )

        recommendation = plan.recommendations[0]
        self.assertIsNone(recommendation.suggested_version)
        self.assertEqual(recommendation.recommendation_status, "requires_manual_review")
        self.assertTrue(any("target-platform wheel compatibility" in warning for warning in recommendation.warnings))

    def test_flask_and_werkzeug_are_checked_together(self):
        compatibility = FakeCompatibility("incompatible")
        releases = {
            "2.2.5": self.release,
            "2.3.8": ReleaseMetadata("2.3.8", ">=3.8", True, True, False),
        }
        plan = FixRecommender(
            pypi=FakePyPI(releases), compatibility=compatibility
        ).build_plan(
            self.target,
            [
                self.finding("Flask", "1.1.2", "PYSEC-2023-62", "2.2.5"),
                self.finding("Werkzeug", "1.0.1", "PYSEC-2023-221", "2.3.8"),
            ],
            "3.14.0",
        )

        self.assertEqual(compatibility.calls, 1)
        self.assertEqual(len(plan.recommendations), 2)
        self.assertEqual(plan.status, "conflict")
        self.assertEqual(
            (self.target / "requirements.txt").read_text(encoding="utf-8"),
            "Flask==1.1.2\nWerkzeug==1.0.1\n",
        )

    def test_pypi_client_handles_404_as_missing_and_network_error(self):
        client = PyPIClient()
        with patch("cybernest.fixes.recommender.urlopen", side_effect=HTTPError(
            "https://pypi.org", 404, "missing", {}, BytesIO()
        )):
            self.assertIsNone(client.release("flask", "2.2.5", "3.14.0"))
        with patch("cybernest.fixes.recommender.urlopen", side_effect=URLError("offline")):
            with self.assertRaises(RuntimeError):
                client.release("werkzeug", "2.3.8", "3.14.0")

    def test_latest_versions_excludes_prereleases_and_returns_descending_stable_versions(self):
        client = PyPIClient()
        payload = {"releases": {
            "3.0.0": [], "3.1.0rc1": [], "2.9.0": [], "3.2.0.dev1": [],
        }}
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = json.dumps(payload).encode()

        with patch("cybernest.fixes.recommender.urlopen", return_value=response):
            versions = client.latest_versions("werkzeug", limit=2)

        self.assertEqual(versions, ["3.0.0", "2.9.0"])

    def test_pypi_429_is_classified_without_caching_transient_failure(self):
        client = PyPIClient()
        limited = HTTPError(
            "https://pypi.org/pypi/flask/2.2.5/json",
            429,
            "rate limited",
            {"Retry-After": "30"},
            BytesIO(b"rate limited"),
        )
        with patch("cybernest.fixes.recommender.urlopen", side_effect=limited) as open_url:
            with self.assertRaises(RuntimeError) as caught:
                client.release("flask", "2.2.5", "3.14.0")
            self.assertEqual(caught.exception.status, "rate_limited")

        payload = {
            "info": {"requires_python": ">=3.8"},
            "urls": [{"packagetype": "bdist_wheel", "yanked": False}],
        }
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = json.dumps(payload).encode()
        with patch("cybernest.fixes.recommender.urlopen", return_value=response) as open_url:
            release = client.release("flask", "2.2.5", "3.14.0")

        self.assertTrue(release.python_compatible)
        open_url.assert_called_once()

    def test_python_range_is_not_collapsed_to_the_running_interpreter(self):
        (self.target / "requirements.txt").unlink()
        (self.target / "pyproject.toml").write_text(
            """[project]
name = "demo"
version = "1.0"
requires-python = ">=3.10,<3.12"
dependencies = ["Flask>=1.1"]
""",
            encoding="utf-8",
        )
        compatibility = FakeCompatibility()
        pypi = FakePyPI({
            "2.2.5": ReleaseMetadata("2.2.5", ">=3.8", True, None, False),
        })

        plan = FixRecommender(pypi=pypi, compatibility=compatibility).build_plan(
            self.target,
            [self.finding("Flask", "1.1.2", "PYSEC-TEST-1", "2.2.5")],
            "3.14.10",
        )

        recommendation = plan.recommendations[0]
        self.assertEqual(plan.python_target, "unknown")
        self.assertEqual(plan.python_target_confidence, "range")
        self.assertEqual(plan.dependency_resolution_status, "python_target_unknown")
        self.assertEqual(recommendation.status, "unknown")
        self.assertIsNone(recommendation.suggested_version)
        self.assertEqual(pypi.calls[0][2], None)
        self.assertEqual(compatibility.calls, 0)

    def test_explicit_python_target_overrides_range_and_is_checked(self):
        (self.target / "requirements.txt").unlink()
        (self.target / "pyproject.toml").write_text(
            """[project]
name = "demo"
version = "1.0"
requires-python = ">=3.10,<3.12"
dependencies = ["Flask>=1.1"]
""",
            encoding="utf-8",
        )
        compatibility = FakeCompatibility()
        plan = FixRecommender(
            pypi=FakePyPI({"2.2.5": self.release}),
            compatibility=compatibility,
        ).build_plan(
            self.target,
            [self.finding("Flask", "1.1.2", "PYSEC-TEST-1", "2.2.5")],
            "3.14.10",
            python_version_override="3.11",
        )

        self.assertEqual(plan.python_target, "3.11")
        self.assertEqual(plan.python_target_source, "cli")
        self.assertEqual(plan.python_target_confidence, "explicit")
        self.assertFalse(plan.python_target_conflict)
        self.assertEqual(compatibility.calls, 1)

    def test_explicit_python_target_outside_project_range_skips_compatibility(self):
        (self.target / "requirements.txt").unlink()
        (self.target / "pyproject.toml").write_text(
            """[project]
name = "demo"
version = "1.0"
requires-python = ">=3.12"
dependencies = ["Flask>=1.1"]
""",
            encoding="utf-8",
        )
        compatibility = FakeCompatibility()
        plan = FixRecommender(
            pypi=FakePyPI({"2.2.5": self.release}),
            compatibility=compatibility,
        ).build_plan(
            self.target,
            [self.finding("Flask", "1.1.2", "PYSEC-TEST-1", "2.2.5")],
            "3.14.10",
            python_version_override="3.11",
        )

        self.assertTrue(plan.python_target_conflict)
        self.assertEqual(plan.dependency_resolution_status, "python_target_conflict")
        self.assertEqual(compatibility.calls, 0)
        self.assertEqual(plan.recommendations[0].compatibility_status, "unknown")

    def test_pypi_release_checks_requires_python_and_yanked_wheels(self):
        payload = {
            "info": {"requires_python": ">=3.12"},
            "urls": [{"packagetype": "bdist_wheel", "yanked": False}],
        }
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = json.dumps(payload).encode()
        with patch("cybernest.fixes.recommender.urlopen", return_value=response):
            release = PyPIClient().release("flask", "2.2.5", "3.11.0")
        self.assertFalse(release.python_compatible)
        self.assertTrue(release.wheel_available)

    @unittest.skipUnless(__import__("sys").platform == "win32", "Windows wheel-tag check")
    def test_pypi_release_distinguishes_sdist_from_target_compatible_wheel(self):
        payload = {
            "info": {"requires_python": ">=3.6"},
            "urls": [
                {
                    "packagetype": "bdist_wheel",
                    "filename": "MarkupSafe-2.0.1-cp310-cp310-win_amd64.whl",
                    "requires_python": ">=3.6",
                    "yanked": False,
                },
                {
                    "packagetype": "sdist",
                    "filename": "MarkupSafe-2.0.1.tar.gz",
                    "yanked": False,
                },
            ],
        }

        py314 = inspect_release_payload(payload, "3.14.10")
        py310 = inspect_release_payload(payload, "3.10")

        self.assertTrue(py314["release_exists"])
        self.assertTrue(py314["any_wheel_available"])
        self.assertFalse(py314["target_wheel_available"])
        self.assertTrue(py314["source_archive_available"])
        self.assertTrue(py310["target_wheel_available"])

    def test_pypi_cache_is_scoped_to_python_version(self):
        payload = {
            "info": {"requires_python": ">=3.12"},
            "urls": [{"packagetype": "bdist_wheel", "yanked": False}],
        }
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = json.dumps(payload).encode()
        client = PyPIClient()
        with patch("cybernest.fixes.recommender.urlopen", return_value=response) as open_url:
            self.assertTrue(client.release("flask", "2.2.5", "3.14.0").python_compatible)
            self.assertFalse(client.release("flask", "2.2.5", "3.11.0").python_compatible)
        self.assertEqual(open_url.call_count, 2)


class TestCompatibilityAnalyzer(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.target = Path(self.temp.name)
        self.requirements = self.target / "requirements.txt"
        self.requirements.write_text("Flask==1.1.2\nWerkzeug==1.0.1\n", encoding="utf-8")
        self.source = read_requirements(self.requirements)
        self.plan = FixPlan(recommendations=[
            FixRecommendation("Flask", "1.1.2", "2.2.5"),
            FixRecommendation("Werkzeug", "1.0.1", "2.3.8"),
        ])
        self.current_dependencies = [
            {"name": "Flask", "version": "1.1.2"},
            {"name": "Werkzeug", "version": "1.0.1"},
            {"name": "Jinja2", "version": "3.1.4"},
            {"name": "MarkupSafe", "version": "2.1.2"},
        ]

    def tearDown(self):
        self.temp.cleanup()

    @patch("cybernest.fixes.compatibility.subprocess.run")
    def test_dry_run_resolves_both_packages_without_modifying_original(self, mock_run):
        def run(command, cwd, **kwargs):
            candidate_req = (Path(cwd) / "requirements.txt").read_text(encoding="utf-8")
            self.assertIn("Flask==2.2.5", candidate_req)
            self.assertIn("Werkzeug==2.3.8", candidate_req)
            report_path = Path(command[command.index("--report") + 1])
            report_path.write_text(json.dumps({"install": [
                {"metadata": {"name": "Flask", "version": "2.2.5"}},
                {"metadata": {"name": "Werkzeug", "version": "2.3.8"}},
                {"metadata": {"name": "Jinja2", "version": "3.1.6"}},
                {"metadata": {"name": "MarkupSafe", "version": "2.1.2"}},
            ]}), encoding="utf-8")
            self.assertIn("--dry-run", command)
            self.assertIn("--ignore-installed", command)
            self.assertEqual(command[command.index("--index-url") + 1], "https://pypi.org/simple")
            return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

        mock_run.side_effect = run
        CompatibilityAnalyzer().analyze(
            self.source, self.plan, "3.14.0", self.current_dependencies
        )

        self.assertEqual(self.plan.dependency_resolution, "resolved")
        self.assertTrue(all(r.compatibility_status == "compatible" for r in self.plan.recommendations))
        self.assertEqual((self.target / "requirements.txt").read_text(encoding="utf-8"),
                         "Flask==1.1.2\nWerkzeug==1.0.1\n")
        self.assertIn({
            "package_name": "jinja2",
            "previous_version": "3.1.4",
            "selected_version": "3.1.6",
            "change": "updated",
        }, self.plan.dependency_changes)
        self.assertEqual(len(self.plan.dependency_changes), 3)

    @patch("cybernest.fixes.compatibility.subprocess.run")
    def test_resolver_tries_bounded_security_validated_candidate_combinations(self, mock_run):
        self.plan.recommendations = [
            FixRecommendation(
                "Flask", "1.1.2", "2.2.5",
                affected_advisories=["CVE-2024-0001"],
                candidate_validations=[
                    {"version": "2.2.5", "status": "verified",
                     "advisory_coverage_status": "complete",
                     "advisory_fixed": ["CVE-2024-0001"]},
                    {"version": "3.1.3", "status": "verified",
                     "candidate_security_audit": {"status": "verified", "coverage_status": "complete"}},
                ],
            ),
            FixRecommendation(
                "Werkzeug", "1.0.1", "2.3.8",
                affected_advisories=["CVE-2024-0002"],
                candidate_validations=[
                    {"version": "2.3.8", "status": "verified",
                     "advisory_coverage_status": "complete",
                     "advisory_fixed": ["CVE-2024-0002"]},
                    {"version": "3.1.9", "status": "verified",
                     "candidate_security_audit": {"status": "verified", "coverage_status": "complete"}},
                ],
            ),
        ]
        attempts = []

        def run(command, cwd, **kwargs):
            text = (Path(cwd) / "requirements.txt").read_text(encoding="utf-8")
            attempts.append(text)
            if "Flask==3.1.3" not in text or "Werkzeug==3.1.9" not in text:
                return type("Completed", (), {
                    "returncode": 1,
                    "stdout": "",
                    "stderr": "ResolutionImpossible: conflicting dependencies",
                })()
            report_path = Path(command[command.index("--report") + 1])
            report_path.write_text(json.dumps({"install": [
                {"metadata": {"name": "Flask", "version": "3.1.3"}},
                {"metadata": {"name": "Werkzeug", "version": "3.1.9"}},
                {"metadata": {"name": "Jinja2", "version": "3.1.6"}},
                {"metadata": {"name": "MarkupSafe", "version": "2.1.2"}},
            ]}), encoding="utf-8")
            return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

        mock_run.side_effect = run
        CompatibilityAnalyzer().analyze(
            self.source, self.plan, "3.14.0", self.current_dependencies
        )

        self.assertEqual(len(attempts), 4)
        self.assertEqual(self.plan.dependency_resolution, "resolved")
        self.assertEqual(self.plan.recommendations[0].suggested_version, "3.1.3")
        self.assertEqual(self.plan.recommendations[1].suggested_version, "3.1.9")
        self.assertEqual(self.plan.dependency_resolution_evidence["candidate_attempts"][-1]["detail"], "resolved")
        self.assertTrue(all(item.compatibility_status == "compatible" for item in self.plan.recommendations))

    @patch("cybernest.fixes.compatibility.subprocess.run")
    def test_confirmed_resolver_conflict_is_incompatible(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = "ResolutionImpossible: conflicting dependencies"
        mock_run.return_value.stdout = ""

        CompatibilityAnalyzer().analyze(
            self.source, self.plan, "3.14.0", self.current_dependencies
        )

        self.assertEqual(self.plan.dependency_resolution, "failed")
        self.assertTrue(all(r.compatibility_status == "incompatible" for r in self.plan.recommendations))

    @patch("cybernest.fixes.compatibility.subprocess.run", side_effect=TimeoutExpired("pip", 75))
    def test_solver_timeout_is_unknown(self, _mock_run):
        CompatibilityAnalyzer().analyze(self.source, self.plan, "3.14.0")
        self.assertTrue(all(r.compatibility_status == "unknown" for r in self.plan.recommendations))

    def test_unsupported_requirements_are_unknown_without_subprocess(self):
        self.requirements.write_text("-e git+https://example.org/repo.git\n", encoding="utf-8")
        source = read_requirements(self.requirements)
        with patch("cybernest.fixes.compatibility.subprocess.run") as mock_run:
            CompatibilityAnalyzer().analyze(source, self.plan, "3.14.0")
        mock_run.assert_not_called()
        self.assertTrue(all(r.compatibility_status == "unknown" for r in self.plan.recommendations))

    @patch("cybernest.fixes.compatibility.subprocess.run")
    def test_missing_inventory_does_not_claim_compatibility(self, mock_run):
        def run(command, cwd, **kwargs):
            report_path = Path(command[command.index("--report") + 1])
            report_path.write_text(json.dumps({"install": [
                {"metadata": {"name": "Flask", "version": "2.2.5"}},
                {"metadata": {"name": "Werkzeug", "version": "2.3.8"}},
            ]}), encoding="utf-8")
            return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

        mock_run.side_effect = run
        CompatibilityAnalyzer().analyze(self.source, self.plan, "3.14.0")

        self.assertEqual(self.plan.dependency_resolution, "resolved")
        self.assertTrue(all(r.compatibility_status == "unknown" for r in self.plan.recommendations))
        self.assertEqual(self.plan.dependency_changes, [])
        self.assertTrue(any("inventory is unavailable" in warning for warning in self.plan.warnings))

    @patch("cybernest.fixes.compatibility.subprocess.run")
    @patch("cybernest.fixes.compatibility.probe_pypi_release", return_value={
        "status": "available",
        "release_exists": True,
        "python_compatible": True,
        "target_wheel_available": False,
        "any_wheel_available": True,
        "source_archive_available": True,
        "source": "PyPI JSON API",
        "url": "https://pypi.org/pypi/markupsafe/2.0.1/json",
    })
    def test_no_matching_wheel_is_unknown_not_a_confirmed_conflict(self, _mock_probe, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = (
            "ERROR: Could not find a version that satisfies the requirement "
            "markupsafe==2.0.1 (from versions: 3.0.3, 3.0.4)\n"
            "ERROR: No matching distribution found for markupsafe==2.0.1"
        )
        mock_run.return_value.stdout = ""

        CompatibilityAnalyzer().analyze(
            self.source, self.plan, "3.14.10", self.current_dependencies
        )

        self.assertEqual(self.plan.dependency_resolution, "failed")
        self.assertEqual(
            self.plan.dependency_resolution_status,
            "no_compatible_wheel_for_target",
        )
        self.assertTrue(all(r.compatibility_status == "unknown" for r in self.plan.recommendations))
        self.assertTrue(any("source builds are disabled" in warning for warning in self.plan.warnings))
        self.assertTrue(any("markupsafe==2.0.1" in warning for warning in self.plan.warnings))
        self.assertTrue(any("Compatibility remains UNKNOWN" in warning for warning in self.plan.warnings))
        self.assertFalse(any("Resolver detail:" in warning for warning in self.plan.warnings))
        self.assertTrue(self.plan.dependency_resolution_evidence["distribution_probe"]["source_archive_available"])

    @patch("cybernest.fixes.compatibility.probe_pypi_release", return_value={
        "status": "not_found", "release_exists": False,
        "source": "PyPI JSON API", "url": "https://pypi.org/pypi/not-a-real-pkg/1.0/json",
    })
    @patch("cybernest.fixes.compatibility.subprocess.run")
    def test_missing_public_release_is_distinguished_from_a_wheel_gap(self, mock_run, _mock_probe):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = (
            "ERROR: No matching distribution found for not-a-real-pkg==1.0"
        )
        mock_run.return_value.stdout = ""

        CompatibilityAnalyzer().analyze(
            self.source, self.plan, "3.14.10", self.current_dependencies
        )

        self.assertEqual(self.plan.dependency_resolution, "failed")
        self.assertEqual(
            self.plan.dependency_resolution_status,
            "release_not_found_on_public_pypi",
        )
        self.assertTrue(all(r.compatibility_status == "unknown" for r in self.plan.recommendations))

    def test_resolver_failure_classes_separate_network_index_and_python_errors(self):
        classify = CompatibilityAnalyzer._classify_resolver_failure

        self.assertEqual(classify("Temporary failure in name resolution"), ("unknown", "network_error"))
        self.assertEqual(classify("403 Client Error: Forbidden"), ("unknown", "index_error"))
        self.assertEqual(classify("Package requires-python >=3.12"), ("incompatible", "python_incompatible"))


if __name__ == "__main__":
    unittest.main()
