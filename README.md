# CyberNest

CyberNest checks Python projects for common security issues. It scans Python
code and looks for known problems in project dependencies.

## Run

You need Python 3.11 or newer. Install CyberNest from the project folder:

```powershell
python -m pip install .
```

Scan a project:

```powershell
cybernest "C:\path\to\project"
```

You can also run it without installing:

```powershell
python -m cybernest.main "C:\path\to\project"
```

Add `--output report.json` to save a report. Use `--overwrite` to replace an
existing report. Add `--suggest-fixes` to check for available package updates.
CyberNest will not install them.

## Checks

- Bandit looks for risky patterns in Python files.
- pip-audit checks project dependencies for known vulnerabilities.

Scans do not run or change the target project. Some dependency checks need an
internet connection. Results can miss issues or include false alarms, so review
them before making changes.

## Tests

```powershell
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
```

CyberNest is in beta. It has been tested on Windows with Python 3.14.10.

## License

No license has been chosen yet.
