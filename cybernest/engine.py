
from pathlib import Path

from cybernest.finding import Finding
from cybernest.integrations.base import BaseScanner
from cybernest.scan_result import ScanResult, ScanStatus


class ScanEngine:
    """CyberNest'in tarama araçlarını yöneten motoru."""

    def __init__(self):
        self.scanners: list[BaseScanner] = []
        self.errors: list[dict[str, str]] = []
        self.results: list[ScanResult] = []

    def register(self, scanner: BaseScanner):
        """Yeni tarayıcı kaydeder."""
        self.scanners.append(scanner)

    def scan(self, target: Path) -> list[Finding]:
        """Tarayıcıları çalıştırır ve bulguları toplar."""

        self.results = []
        findings = []
        self.errors = []

        for scanner in self.scanners:
            print(f"[+] Running scanner: {scanner.name}")

            try:
                if hasattr(scanner, "scan_with_status"):
                    result = scanner.scan_with_status(target)
                else:
                    scanner_findings = scanner.scan(target)
                    result = ScanResult(
                        scanner=scanner.name,
                        status=ScanStatus.SUCCESS,
                        findings=scanner_findings,
                    )

                self.results.append(result)

                if result.status == ScanStatus.SUCCESS:
                    findings.extend(result.findings)
                    print(
                        f"[OK] {scanner.name}: "
                        f"{len(result.findings)} findings"
                    )
                elif result.status == ScanStatus.FAILED:
                    self.errors.append({
                        "scanner": scanner.name,
                        "message": result.message,
                    })
                    print(f"[ERROR] {scanner.name}: {result.message}")
                elif result.status == ScanStatus.SKIPPED:
                    print(f"[SKIPPED] {scanner.name}: {result.message}")

            except Exception as error:
                self.results.append(
                    ScanResult(
                        scanner=scanner.name,
                        status=ScanStatus.FAILED,
                        message=str(error),
                    )
                )
                self.errors.append({
                    "scanner": scanner.name,
                    "message": str(error),
                })

                print(f"[ERROR] {scanner.name}: {error}")

        return findings
