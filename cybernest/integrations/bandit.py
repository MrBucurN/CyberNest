import json
import os
import subprocess
import sys
from fnmatch import fnmatchcase
from pathlib import Path

from cybernest.finding import Finding
from cybernest.integrations.base import BaseScanner
from cybernest.scan_result import ScanResult, ScanStatus


class BanditScanner(BaseScanner):
    """Run Bandit against Python source files in a project."""

    name = "bandit"
    excluded_directories = {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".tox",
        ".nox",
        "build",
        "dist",
        "*.egg-info",
    }

    def scan(self, target: Path) -> list[Finding]:
        return self.scan_with_status(target).findings

    def scan_with_status(self, target: Path) -> ScanResult:
        target = Path(target).resolve()
        if not target.is_dir():
            return self._result(
                ScanStatus.FAILED,
                message="Target directory does not exist.",
                coverage="unknown",
            )

        source_count = self._count_python_files(target)
        if source_count == 0:
            return self._result(
                ScanStatus.SKIPPED,
                message="No Python source files were found.",
                coverage="incomplete",
                source_count=0,
            )

        command = [
            sys.executable,
            "-m",
            "bandit",
            "-r",
            ".",
            "-f",
            "json",
            "-q",
            "-x",
            ",".join(sorted(self.excluded_directories)),
        ]

        try:
            completed = subprocess.run(
                command,
                cwd=target,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return self._result(
                ScanStatus.FAILED,
                message="Bandit scan timed out after 120 seconds.",
                coverage="incomplete",
                source_count=source_count,
            )
        except OSError as error:
            return self._result(
                ScanStatus.FAILED,
                message=f"Unable to start Bandit: {error}",
                coverage="incomplete",
                source_count=source_count,
            )

        if completed.returncode not in {0, 1}:
            detail = completed.stderr.strip() or completed.stdout.strip()
            return self._result(
                ScanStatus.FAILED,
                message=detail or f"Bandit exited with status {completed.returncode}.",
                coverage="incomplete",
                source_count=source_count,
            )

        try:
            report = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            return self._result(
                ScanStatus.FAILED,
                message=f"Bandit returned invalid JSON: {error}",
                coverage="incomplete",
                source_count=source_count,
            )

        if (
            not isinstance(report, dict)
            or not isinstance(report.get("results"), list)
            or not isinstance(report.get("errors", []), list)
        ):
            return self._result(
                ScanStatus.FAILED,
                message="Bandit returned an unexpected report format.",
                coverage="incomplete",
                source_count=source_count,
            )

        findings = [
            self._to_finding(item)
            for item in report["results"]
            if isinstance(item, dict) and item.get("issue_text")
        ]
        errors = report.get("errors", [])
        coverage = "incomplete" if errors else "complete"
        message = (
            f"Scanned {source_count} Python files; Bandit reported {len(findings)} findings."
            if not errors
            else f"Scanned with {len(errors)} file errors; results may be incomplete."
        )
        return self._result(
            ScanStatus.SUCCESS,
            findings=findings,
            message=message,
            coverage=coverage,
            source_count=source_count,
            errors=errors,
        )

    def _count_python_files(self, target: Path) -> int:
        count = 0
        for current, directories, filenames in os.walk(target):
            directories[:] = [
                name
                for name in directories
                if not self._is_excluded_directory(name)
            ]
            count += sum(filename.lower().endswith(".py") for filename in filenames)
        return count

    @classmethod
    def _is_excluded_directory(cls, name: str) -> bool:
        return any(fnmatchcase(name, pattern) for pattern in cls.excluded_directories)

    @staticmethod
    def _to_finding(item: dict) -> Finding:
        filename = Path(str(item.get("filename", "")))
        line_number = item.get("line_number")
        if not isinstance(line_number, int):
            line_number = None
        severity = str(item.get("issue_severity", "UNKNOWN")).upper()
        if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}:
            severity = "UNKNOWN"

        test_id = str(item.get("test_id", ""))
        test_name = str(item.get("test_name", ""))
        return Finding(
            title=str(item["issue_text"]),
            severity=severity,
            tool="bandit",
            category="source_code",
            affected_component=filename.name,
            description=str(item.get("issue_text", "")),
            file_path=filename.as_posix(),
            line_number=line_number,
            evidence=" ".join(value for value in (test_id, test_name) if value),
            recommendation=str(item.get("more_info", "Review this Bandit finding.")),
        )

    @staticmethod
    def _result(
        status: ScanStatus,
        *,
        findings: list[Finding] | None = None,
        message: str,
        coverage: str,
        source_count: int = 0,
        errors: list | None = None,
    ) -> ScanResult:
        return ScanResult(
            scanner=BanditScanner.name,
            status=status,
            findings=findings or [],
            message=message,
            scope={
                "scanner": BanditScanner.name,
                "status": status.value,
                "coverage_status": coverage,
                "source_files_scanned": source_count,
                "source_scan_errors": errors or [],
            },
        )
