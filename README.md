# CyberNest

**Security That Leads to a Fix**

CyberNest is a local-first command-line tool for scanning Python dependency
manifests, explaining vulnerability findings, evaluating update candidates,
and comparing scans after a user updates dependencies.

## Project status

CyberNest is the `1.0.0b1` beta candidate, not a stable v1.0 release. It has
been validated on Windows with PowerShell and CPython 3.14.10. Other operating
systems and a native Python 3.11 runtime were not available for validation.
Selecting another Python target does not change the interpreter running
pip-audit; cross-interpreter vulnerability resolution is reported as
incomplete.

## Requirements and installation

- Python 3.11 or later.
- Network access for pip-audit vulnerability data, package resolution, NVD / 
  GitHub CVSS enrichment, and PyPI release validation.

Install from a checkout in PowerShell:

```powershell
python -m pip install .
```

The installed command is `cybernest`. The module form is:

```powershell
python -m cybernest.main --help
```

The older `python -m src.main` command remains available from a source
checkout for compatibility. The wheel contains only the `cybernest` package;
the source distribution retains the small `src` compatibility shim.

For a downloaded GitHub release wheel, install the wheel from its download
folder:

```powershell
python -m pip install .\cybernest_security_scanner-1.0.0b1-py3-none-any.whl
```

Run the test suite from a checkout:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m build
```

The `dev` extra installs the PEP 517 build frontend. The build command creates
the wheel and source distribution in `dist/`.

## Supported dependency inputs

CyberNest discovers these inputs under the project directory:

- `requirements*.txt` and `requirements*.in`, including nested `-r` and `-c`
  files whose resolved paths stay inside the project.
- Static PEP 621 dependencies in `pyproject.toml`. Each declared optional
  dependency group is scanned as its own dependency context.
- `[options] install_requires` in `setup.cfg`.

Environment markers, extras, version ranges, comments, and blank lines are
passed to pip-audit. Requirements include cycles, paths outside the project,
invalid PEP 508 entries, private-index options, editable inputs, and direct
URL / VCS / local dependencies are reported as unsupported for that manifest.
Dynamic PEP 621 dependencies, PEP 735 groups, setup.cfg extras, setup.py,
Pipenv / PDM / Conda manifests, Poetry / uv / PDM lockfiles, and package-manager
dependency sources or groups are not silently treated as scanned. If any
discovered input is unsupported or fails, scan coverage is marked incomplete.

Each supported manifest or optional group is resolved separately. CyberNest
reports `resolved_version` for versions produced by pip-audit's requirements
resolver. The legacy `installed_version` field remains in JSON for compatibility
and mirrors that resolved value for manifest scans; it does not mean that
CyberNest inspected the target's installed environment. Findings also carry a
direct / transitive indicator and the declared specifier when available.
Coverage metadata records declared, scanned, not-applicable, and unscanned
direct dependencies, resolved transitive package counts, per-manifest status,
and the reason for any partial result. Scanner execution, security coverage,
and fix-plan resolution are separate report fields. A successful scanner run
can still have incomplete dependency coverage. When exact-pinned direct
dependencies can be scanned after transitive resolution fails, CyberNest
records the failure class and affected exact requirement. For a binary wheel
gap, it checks public PyPI release metadata and reports whether a matching
wheel or source archive exists. Source archives are never built by the scanner;
their presence does not establish installability.

## Python target version

CyberNest reads a single version from `.python-version` or an exact
`project.requires-python` / `setup.cfg` requirement. A broad Python version
range is kept as a range; it is not silently reduced to one version. Select a
specific compatibility target with:

```powershell
cybernest "C:\path\to\project" --python-version 3.11
```

If no target is declared, fix compatibility uses the running interpreter as an
explicit assumption and reports that source and confidence in JSON. When the
selected target differs from the Python interpreter running pip-audit, the
scan is marked incomplete: pip-audit currently resolves environment markers
and distributions under its own interpreter. Use a matching Python runtime for
a complete cross-version dependency scan.

## Scan and report

Scan a project:

```powershell
cybernest "C:\path\to\project"
```

Save a baseline report:

```powershell
cybernest "C:\path\to\project" --output baseline.json
```

Existing reports are never overwritten by default. Pass `--overwrite` only
when replacement is intended:

```powershell
cybernest "C:\path\to\project" --output baseline.json --overwrite
```

The CLI reports scanner status, coverage, severity counts, affected packages,
and a short list of priority findings. The default finding view shows the CVSS
score, version, lookup state, and source when available. Use `--verbose` to
include CVSS vectors and source URLs, advisory aliases, descriptions,
applicability notes, and other finding metadata.

## CVSS and applicability

For CVE and GHSA identifiers, CyberNest queries NVD and the GitHub Advisory
Database. It validates the returned CVSS score and vector, checks NVD CVE
identity, and applies a deterministic source policy: NVD Primary, GitHub
Advisory Database, other NVD Primary metrics, then NVD Secondary metrics.
CVSS version breaks ties within the same source tier. The selected score,
vector, version, source, URL, reported severity, and selection reason remain
together in the finding.

No score is inferred from prose. Missing records show `UNKNOWN`; network errors,
API errors, and rate limits have separate lookup statuses. Validated CVSS
results are cached in memory and in a per-user cache for one hour. On Windows
the cache is stored at `%LOCALAPPDATA%\CyberNest\cvss-cache-v1.json`; on other
systems it uses the XDG data directory or `~/.local/share/cybernest/`. The
cache is schema-versioned, written atomically, and stores validated advisory
metadata only. Transient errors and `not_available` responses are not persisted.
The CLI and JSON report identify whether a result came from a live lookup or
the cache and include cache age when available. Provider rate limits use a
bounded cooldown and still allow a lookup through an available alias at the
other provider. Cache read/write failures do not fail the scan.

CVSS is not an application-specific risk assessment. Applicability remains
`unknown` unless the advisory itself requires review; disputed advisories are
flagged for review. CyberNest does not infer that a finding is not applicable
from the project's operating system, runtime, configuration, or usage.

## Fix recommendations and compatibility

Get read-only update recommendations:

```powershell
cybernest "C:\path\to\project" --suggest-fixes
```

Stable advisory-listed versions and a bounded set of latest stable PyPI
releases are checked against PyPI metadata and the selected Python target. When
available, an exact-version, no-dependency `pip-audit` check evaluates each
candidate against its current advisory database. A clean candidate audit means
that audit reported no known vulnerabilities; it does not establish runtime
safety or guarantee future results. Alias records are grouped into canonical
advisories so one finding is not counted multiple times. `complete`, `partial`,
`no_known_fix`, `manual_review`, and `unknown` are distinct recommendation
states. Security coverage, PyPI release validation, and dependency
compatibility are separate fields. When pip proves that the selected pins
conflict, the resolver checks at most four combinations of security-validated
candidate versions before reporting the result.

The project-level compatibility check uses pip's dry-run report, a temporary
requirements file, the public PyPI index, and binary distributions only. It
does not install packages or edit the target project. Source builds are
disabled to avoid executing untrusted build backends. A failure can mean a
confirmed dependency conflict, Python incompatibility, a missing compatible
binary distribution, an index/network error, timeout, or unsupported input;
ambiguous cases remain `unknown`.

When pip cannot resolve an exact release, CyberNest checks the matching PyPI
release metadata to distinguish an absent public release from a release with
no target-compatible wheel. It reports whether a source archive exists, but
does not build it or treat it as proof that installation will succeed.

For example, this checkout's Flask fixture pins `MarkupSafe==2.0.1`. In the
current Windows CPython 3.14.10 environment PyPI has the release as a source
archive and older interpreter wheels, but no matching CPython 3.14 Windows
wheel. The binary-only resolver therefore reports `unknown`. A Python 3.10
binary dry run finds the MarkupSafe wheel, while the proposed Werkzeug 2.2.3
requires MarkupSafe 2.1.1 or newer and conflicts with the fixture's exact
2.0.1 pin. These are environment and dependency-set findings, not proof that
the source release is missing or unbuildable.

Compatibility success does not prove that the application starts or behaves
correctly at runtime. Recommendations do not apply updates automatically.

## Known limitations

- Native runtime validation in this beta was performed on Windows CPython
  3.14.10. Python 3.11 and other operating systems were not available for a
  native test run.
- Poetry, uv, PDM, Pipenv, Conda, and other unsupported lockfiles or dependency
  groups are reported as unsupported; their packages are not silently counted
  as scanned.
- Transitive dependency coverage can remain incomplete when the selected
  Python/platform has no usable binary distribution or the package index cannot
  be reached. CyberNest does not build source distributions or execute project
  code to overcome that limitation.
- CyberNest evaluates dependency advisories and candidate releases. It does not
  test application startup, runtime behavior, or whether a vulnerability is
  reachable in the project's usage.

## Rescan and verification

Save a baseline before changing dependencies, then compare the new scan:

```powershell
cybernest "C:\path\to\project" --output baseline.json
# Update dependencies yourself, then:
cybernest "C:\path\to\project" --compare baseline.json --output after-update.json
```

Verification matches package, ecosystem, scanner, and advisory identifiers,
including aliases. It reports full-project `resolved`, `remaining`, and `new`
findings only when target, scanner set, and coverage match. Failed or skipped
scanners, unsupported inputs, changed scope, or legacy reports without
sufficient metadata make the overall result inconclusive rather than resolved.
When full coverage is incomplete, CyberNest can separately compare the exact
same non-empty direct dependency inventory if both reports record matching
targets, scanners, manifests, package sets, and complete direct-dependency
coverage. This scoped result never changes the overall project status; it does
not claim transitive or whole-project verification.

## JSON report

Reports use schema version `1.2` and preserve the earlier `scans` section while
adding scan metadata, scanner results, normalized canonical IDs and aliases,
severity counts, dependency inventory, fix recommendations, verification, and
warnings. CVSS enrichment fields include score, vector, version, source, lookup
status, data origin, and cache age where known. Verification includes the
overall status and, when supported, a separate direct-dependency scoped result.
The report includes the target path for rescan matching; it does not include
project source contents or environment variables. Reports are written
atomically, and replacement requires `--overwrite`.

## Exit codes

- `0`: complete scan with no reported findings.
- `1`: complete scan with one or more findings.
- `2`: invalid command-line usage (argparse).
- `3`: incomplete or inconclusive scan coverage.
- `4`: target, scan operation, comparison, or report I/O error.

When coverage is incomplete, exit code `3` takes precedence over findings.

## Network and privacy

Project manifests are read locally. pip-audit and the compatibility resolver
contact package indexes to resolve package metadata; severity enrichment sends
advisory identifiers to NVD or GitHub. These requests require network access.
CyberNest does not upload source files, run project code, install proposed
updates, or change the target project's dependency files during its normal
scan and fix-analysis workflow. Private index and direct URL requirements are
reported as unsupported rather than followed automatically.

## License

No license has been selected for this repository. A license must be chosen and
its official text added before public redistribution. Common choices include
MIT for a short permissive license, Apache-2.0 for permissive terms with
explicit patent provisions, and GPL-3.0 for a copyleft license. This note does
not grant permission to reuse the project.
