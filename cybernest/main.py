
import argparse
import json
import sys
from pathlib import Path
from packaging.version import InvalidVersion, Version

from cybernest.engine import ScanEngine
from cybernest.integrations.bandit import BanditScanner
from cybernest.integrations.pip_audit import PipAuditScanner
from cybernest.fixes.recommender import FixRecommender
from cybernest.fixes.verification import compare_reports
from cybernest.reports.json_report import build_report, save_report
from cybernest.scan_result import ScanStatus


def main():
    parser = argparse.ArgumentParser(
        description="Scan Python source code and dependencies for security issues."
    )
    parser.add_argument("project_path")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument(
        "--suggest-fixes",
        action="store_true",
        help="Validate security update candidates and dependency compatibility without changing files.",
    )
    parser.add_argument(
        "--compare",
        type=Path,
        default=None,
        help="Compare this scan with a previous CyberNest JSON report.",
    )
    parser.add_argument(
        "--python-version",
        default=None,
        help="Python target used for fix compatibility checks (for example 3.11).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show full finding details and descriptions.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace the report file specified by --output.",
    )
    args = parser.parse_args()

    if args.python_version:
        try:
            target_python = Version(args.python_version)
        except InvalidVersion:
            parser.error("--python-version must be a valid Python version such as 3.11 or 3.11.8.")
        if (
            len(target_python.release) not in {2, 3}
            or target_python.is_prerelease
            or target_python.is_devrelease
            or target_python.local is not None
        ):
            parser.error("--python-version must contain a stable major.minor or major.minor.micro version.")
        args.python_version = str(target_python)

    target = Path(args.project_path).resolve()

    if not target.is_dir():
        print(f"\nTarget directory not found: {target}")
        sys.exit(4)

    print(f"\nTarget: {target}")

    engine = ScanEngine()

    engine.register(BanditScanner())
    engine.register(PipAuditScanner(python_target_override=args.python_version))

    try:
        findings = engine.scan(target)
    except Exception as error:
        print(f"\nScan failed: {error}")
        sys.exit(4)

    fix_plan = None
    fix_plan_error = ""
    if args.suggest_fixes:
        python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        try:
            dependency_inventory = next(
                (
                    result.dependencies
                    for result in engine.results
                    if result.scanner == "pip-audit" and result.status == ScanStatus.SUCCESS
                ),
                None,
            )
            fix_plan = FixRecommender().build_plan(
                target,
                findings,
                python_version,
                current_dependencies=dependency_inventory,
                python_version_override=args.python_version,
            )
        except Exception as error:
            fix_plan_error = f"Fix recommendation analysis could not complete: {error}"

    verification = None
    if args.compare is not None:
        try:
            previous = json.loads(args.compare.read_text(encoding="utf-8"))
            if not isinstance(previous, dict):
                raise ValueError("Previous report must be a JSON object.")
            current = build_report(engine.results, target=target)
            verification = compare_reports(previous, current)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            print(f"\nUnable to compare previous report: {error}")
            sys.exit(4)

    report_saved_path = None
    if args.output is not None:
        try:
            report = build_report(
                engine.results,
                target=target,
                fix_plan=fix_plan.to_dict() if fix_plan is not None else None,
                verification=verification.to_dict() if verification is not None else None,
            )
            save_report(report, args.output, overwrite=args.overwrite)
            report_saved_path = args.output
        except FileExistsError:
            print(
                f"\nReport already exists: {args.output}\n"
                "Choose another filename or pass --overwrite explicitly."
            )
            sys.exit(4)
        except OSError as error:
            print(f"\nUnable to save report to {args.output}: {error}")
            sys.exit(4)

    print("\n========== SCAN SUMMARY ==========")
    if not engine.results:
        print("\nNo scanners executed.")
    else:
        for result in engine.results:
            print(f"\nScanner: {result.scanner}")
            print(f"Status: {result.status.value.upper()}")
            print(f"Message: {result.message}")
            print(f"Findings: {len(result.findings)}")
            coverage = result.scope.get("coverage_status", "unknown") if result.scope else "unknown"
            print(f"Coverage: {str(coverage).upper()}")
            dependency_coverage = (
                result.scope.get("dependency_coverage", {}) if result.scope else {}
            )
            if isinstance(dependency_coverage, dict):
                direct = dependency_coverage.get("direct_dependencies", {})
                transitive = dependency_coverage.get("transitive_dependencies", {})
                if isinstance(direct, dict) and isinstance(transitive, dict):
                    print(
                        "Direct dependencies: "
                        f"{direct.get('scanned_count', 0)}/{direct.get('declared_count', 0)} scanned; "
                        f"{direct.get('not_applicable_count', 0)} not applicable; "
                        f"{direct.get('unscanned_count', 0)} unscanned"
                    )
                    print(
                        "Transitive dependencies: "
                        f"{transitive.get('scanned_count', 0)} scanned; "
                        f"{str(transitive.get('status', 'unknown')).upper()}"
                    )
                    for manifest in dependency_coverage.get("manifests", []):
                        if not isinstance(manifest, dict):
                            continue
                        if args.verbose or manifest.get("status") != "complete":
                            print(
                                f"Dependency file: {manifest.get('manifest', 'unknown')} "
                                f"[{str(manifest.get('status', 'unknown')).upper()}]"
                            )
                            if manifest.get("reason"):
                                print(f"  Coverage reason: {manifest['reason']}")
    print("\n==================================")

    incomplete = not engine.results or any(
        result.status != ScanStatus.SUCCESS
        or not result.scope
        or result.scope.get("coverage_status", "unknown") != "complete"
        for result in engine.results
    )
    if not engine.results:
        print("\n[WARNING] No security checks were executed.")
        print("The security assessment is incomplete.")
    elif incomplete:
        print("\n[WARNING] Some security checks were skipped or failed.")
        print("The security assessment is incomplete.")

    if not findings:
        if engine.results and not incomplete:
            scanned_packages = sum(
                int(result.scope.get("dependency_coverage", {}).get("scanned_dependency_count", 0))
                for result in engine.results
                if isinstance(result.scope.get("dependency_coverage", {}), dict)
            )
            if scanned_packages:
                print(
                    f"\nNo known vulnerabilities reported among {scanned_packages} scanned dependency records."
                )
            else:
                print("\nNo applicable dependencies were found; 0 packages were scanned.")
        elif engine.results:
            print(
                "\nSome scans did not complete successfully; "
                "the results are inconclusive."
            )
        _print_post_scan_sections(
            fix_plan, verification, report_saved_path, fix_plan_error, args.verbose
        )
        return 3 if incomplete else 0

    count = len(findings)
    word = "finding" if count == 1 else "findings"
    print(f"\nFound {count} security {word}:\n")

    severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NONE": 1, "UNKNOWN": 0}
    severity_counts = {name: 0 for name in severity_order}
    affected_counts: dict[str, int] = {}
    for finding in findings:
        severity = finding.severity.upper()
        severity_counts[severity if severity in severity_counts else "UNKNOWN"] += 1
        if finding.affected_component:
            affected_counts[finding.affected_component] = (
                affected_counts.get(finding.affected_component, 0) + 1
            )
    print("Findings by severity: " + ", ".join(
        f"{name} {severity_counts[name]}"
        for name in severity_order
        if severity_counts[name]
    ))
    if affected_counts:
        print("Affected items: " + ", ".join(
            f"{name} ({amount})"
            for name, amount in sorted(
                affected_counts.items(),
                key=lambda item: (-item[1], item[0].casefold()),
            )[:10]
        ))
    ordered_findings = sorted(
        findings,
        key=lambda item: (-severity_order.get(item.severity.upper(), 0), item.title.casefold()),
    )
    shown_findings = ordered_findings if args.verbose else ordered_findings[:5]
    for finding in shown_findings:
        print("-" * 45)
        if finding.category == "source_code":
            print(f"[{finding.severity}] {finding.title}")
        else:
            version = finding.resolved_version or finding.installed_version
            print(
                f"[{finding.severity}] {finding.affected_component} "
                f"{version}: {finding.title}"
            )
        if finding.file_path:
            location = finding.file_path
            if finding.line_number is not None:
                location = f"{location}:{finding.line_number}"
            print(f"Location: {location}")
        if finding.fixed_version:
            print(f"Known fixed versions: {finding.fixed_version}")
        if finding.reported_severity and finding.reported_severity != finding.severity:
            print(f"Advisory severity: {finding.reported_severity}")
        if finding.severity_lookup_status:
            print(f"CVSS score: {finding.cvss_score}")
            print(f"CVSS version: {finding.cvss_version or 'UNKNOWN'}")
            print(f"Lookup status: {finding.severity_lookup_status}")
            if finding.severity_data_origin:
                print(f"Data origin: {finding.severity_data_origin}")
            if finding.severity_cache_age_seconds is not None:
                print(f"Cache age: {finding.severity_cache_age_seconds:.1f}s")
        if args.verbose and finding.cvss_vector:
            print(f"CVSS vector: {finding.cvss_vector}")
        if finding.severity_source:
            print(f"Source: {finding.severity_source}")
        if args.verbose and finding.severity_source_url:
            print(f"Source URL: {finding.severity_source_url}")
        print(f"Applicability: {finding.applicability_status.upper()}")
        if finding.applicability_reason:
            print(f"Applicability note: {finding.applicability_reason}")
        for warning in finding.advisory_warnings:
            print(f"Warning: {warning}")
        if args.verbose:
            print(f"Tool: {finding.tool}")
            print(f"Category: {finding.category}")
            print(f"Evidence: {finding.evidence}")
            print(f"Description: {finding.description}")
            print(f"Recommendation: {finding.recommendation}")

    if not args.verbose and len(ordered_findings) > len(shown_findings):
        print(f"... {len(ordered_findings) - len(shown_findings)} more findings; use --verbose to show all details.")

    print("-" * 45)
    _print_post_scan_sections(
        fix_plan, verification, report_saved_path, fix_plan_error, args.verbose
    )
    return 3 if incomplete else 1


def _print_post_scan_sections(fix_plan, verification, report_saved_path, fix_plan_error, verbose):
    if fix_plan_error:
        print(f"\n{fix_plan_error}")
    if fix_plan is not None:
        _print_fix_plan(fix_plan, verbose)
    if verification is not None:
        _print_verification(verification)
    if report_saved_path is not None:
        print(f"Report saved: {report_saved_path}")


def _print_fix_plan(fix_plan, verbose):
    print("\n========== FIX PLAN ==========")
    print(f"Plan status: {fix_plan.status}")
    print(f"Dependency resolution: {fix_plan.dependency_resolution}")
    print(f"Dependency resolution detail: {fix_plan.dependency_resolution_status}")
    resolver_evidence = fix_plan.dependency_resolution_evidence
    attempts = resolver_evidence.get("candidate_attempts", [])
    if isinstance(attempts, list) and len(attempts) > 1:
        print(f"Resolver candidate combinations checked: {len(attempts)}")
    distribution_probe = resolver_evidence.get("distribution_probe", {})
    if isinstance(distribution_probe, dict) and distribution_probe:
        print(
            f"Resolver evidence: {distribution_probe.get('package', 'unknown')}=="
            f"{distribution_probe.get('version', 'unknown')} on public PyPI; "
            f"target wheel={distribution_probe.get('target_wheel_available', 'unknown')}; "
            f"source archive={distribution_probe.get('source_archive_available', 'unknown')}"
        )
    for item in fix_plan.recommendations:
        proposed = item.suggested_version or "no verified candidate"
        print(
            f"{item.package_name}: {item.installed_version} -> {proposed}; "
            f"compatibility={item.compatibility_status}; "
            f"recommendation={item.recommendation_status}; status={item.status}"
        )
        print(
            f"  Release validation: {item.release_validation_status}; "
            f"security coverage: {item.security_coverage_status}"
        )
        print(
            f"  Exact candidate audit: {item.candidate_audit_status}"
            + (f" ({item.candidate_audit_source})" if item.candidate_audit_source else "")
        )
        if verbose:
            for canonical_id, aliases in item.advisory_aliases.items():
                if aliases:
                    print(f"  Aliases for {canonical_id}: {', '.join(aliases)}")
        if item.addressed_advisories:
            print(f"  Addressed advisories: {', '.join(item.addressed_advisories)}")
        if item.remaining_advisories:
            print(f"  Remaining advisories: {', '.join(item.remaining_advisories)}")
        if item.unverified_advisories:
            print(f"  Unverified advisories: {', '.join(item.unverified_advisories)}")
        if item.new_advisories:
            print(f"  Additional candidate advisories: {', '.join(item.new_advisories)}")
        print(f"  Reason: {item.reason}")
        for warning in item.warnings:
            print(f"  Warning: {warning}")
    for warning in fix_plan.warnings:
        print(f"Warning: {warning}")
    print("No project files or installed packages were changed.")


def _print_verification(verification):
    print("\n========== FIX VERIFICATION ==========")
    print(f"Status: {verification.status}")
    print(f"Scope: {verification.scope_status}")
    print(f"Resolved: {len(verification.resolved)}")
    print(f"Remaining: {len(verification.remaining)}")
    print(f"New: {len(verification.new)}")
    scoped = verification.scoped_verification
    if isinstance(scoped, dict):
        print(f"Overall status: {verification.status.upper()}")
        print(
            f"Scoped verification: {scoped.get('status', 'inconclusive').upper()} "
            f"({scoped.get('scope', 'direct_dependencies')})"
        )
        print(
            f"Scoped previous findings: {scoped.get('previous_findings', 0)}; "
            f"current findings: {scoped.get('current_findings', 0)}"
        )
        print(
            f"Scoped resolved: {len(scoped.get('resolved', []))}; "
            f"remaining: {len(scoped.get('remaining', []))}; "
            f"new: {len(scoped.get('new', []))}"
        )
    for label, entries in (
        ("Resolved findings", verification.resolved),
        ("Remaining findings", verification.remaining),
        ("New findings", verification.new),
    ):
        if not entries:
            continue
        print(f"\n{label}:")
        for entry in entries:
            if "current" in entry:
                entry = entry["current"]
            elif "previous" in entry:
                entry = entry["previous"]
            print(f"- {entry.get('title', 'Unknown advisory')}")
    for warning in verification.warnings:
        print(f"Warning: {warning}")


if __name__ == "__main__":
    raise SystemExit(main())
