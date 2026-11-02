"""Verify a proposed package version with pip-audit without resolving or installing it."""

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version


@dataclass(frozen=True)
class CandidateAuditResult:
    status: str
    package_name: str
    version: str
    advisories: list[dict[str, object]] = field(default_factory=list)
    error: str = ""


class PipAuditCandidateAuditor:
    """Use pip-audit's exact-pin, no-dependency mode for one candidate release."""

    TIMEOUT_SECONDS = 20

    def audit(self, package_name: str, version: str) -> CandidateAuditResult:
        try:
            Version(version)
        except InvalidVersion:
            return CandidateAuditResult("invalid_version", package_name, version)

        with tempfile.TemporaryDirectory(prefix="cybernest-candidate-audit-") as directory:
            work = Path(directory)
            requirements = work / "requirements.txt"
            requirements.write_text(
                f"{package_name}=={version}\n", encoding="utf-8"
            )
            environment = {
                key: value for key, value in os.environ.items()
                if not key.upper().startswith("PIP_")
            }
            environment["PIP_CONFIG_FILE"] = os.devnull
            environment["PIP_ONLY_BINARY"] = ":all:"
            command = [
                sys.executable, "-m", "pip_audit",
                "--requirement", str(requirements),
                "--no-deps", "--disable-pip", "--format", "json",
            ]
            try:
                result = subprocess.run(
                    command, cwd=work, capture_output=True, text=True,
                    timeout=self.TIMEOUT_SECONDS, check=False, env=environment,
                )
            except subprocess.TimeoutExpired:
                return CandidateAuditResult("timeout", package_name, version)
            except OSError as error:
                return CandidateAuditResult(
                    "process_error", package_name, version, error=type(error).__name__
                )

        if result.returncode not in (0, 1):
            return CandidateAuditResult(
                "audit_error", package_name, version,
                error=(result.stderr or result.stdout).strip()[-600:],
            )
        try:
            payload = json.loads(result.stdout)
            dependencies = payload["dependencies"]
            if not isinstance(dependencies, list):
                raise ValueError("dependencies was not a list")
            matching = [
                dependency for dependency in dependencies
                if isinstance(dependency, dict)
                and canonicalize_name(str(dependency.get("name", "")))
                == canonicalize_name(package_name)
            ]
            if len(matching) != 1:
                raise ValueError("candidate was not uniquely present in pip-audit output")
            actual = matching[0].get("version")
            if not isinstance(actual, str) or Version(actual) != Version(version):
                raise ValueError("pip-audit did not confirm the requested candidate version")
            vulnerabilities = matching[0].get("vulns", [])
            if not isinstance(vulnerabilities, list) or any(
                not isinstance(item, dict) or not isinstance(item.get("id"), str)
                for item in vulnerabilities
            ):
                raise ValueError("candidate vulnerability records were invalid")
        except (json.JSONDecodeError, KeyError, TypeError, ValueError, InvalidVersion) as error:
            return CandidateAuditResult(
                "invalid_report", package_name, version, error=str(error)
            )
        return CandidateAuditResult(
            "verified", package_name, version,
            advisories=[dict(item) for item in vulnerabilities],
        )
