"""Discover dependency manifests that CyberNest can scan without guessing."""

import configparser
import os
import re
import shlex
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version


_EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "__pycache__",
    "node_modules", "site-packages", "build", "dist", ".tox", ".mypy_cache",
}
_UNSUPPORTED_LOCKFILES = {"poetry.lock", "uv.lock", "pipfile.lock"}
_UNSUPPORTED_PROJECT_FILES = {
    "setup.py", "pipfile", "environment.yml", "environment.yaml", "pdm.lock",
}


@dataclass
class DependencyManifest:
    path: Path
    format: str
    group: str = "main"
    display_path: str = ""
    requirements: list[str] = field(default_factory=list)
    direct_dependencies: list[dict[str, str | bool]] = field(default_factory=list)
    included_files: list[Path] = field(default_factory=list)
    unsupported_reason: str = ""

    @property
    def label(self) -> str:
        relative = self.display_path or self.path.name
        return f"{relative}[{self.group}]" if self.group != "main" else relative


@dataclass
class ProjectDiscovery:
    root: Path
    manifests: list[DependencyManifest] = field(default_factory=list)
    unsupported_files: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    requires_python: str = ""
    python_target: str = ""
    python_target_source: str = ""
    python_target_confidence: str = "unknown"
    python_target_conflict: bool = False

    @property
    def coverage_complete(self) -> bool:
        return bool(self.manifests) and not self.unsupported_files and not self.warnings


def discover_project(root: Path) -> ProjectDiscovery:
    root = root.resolve()
    result = ProjectDiscovery(root=root)
    files = _walk_files(root)

    requirements_paths = sorted(
        (path for path in files if path.name.casefold().startswith("requirements")
         and path.suffix.casefold() in {".txt", ".in"}),
        key=lambda path: path.as_posix().casefold(),
    )
    for path in requirements_paths:
        manifest = DependencyManifest(
            path=path, format="requirements", display_path=_relative(root, path)
        )
        _inspect_requirements(path, root, manifest)
        result.manifests.append(manifest)
        if manifest.unsupported_reason:
            result.unsupported_files.append(_relative(root, path))
            result.warnings.append(
                f"{_relative(root, path)} was not scanned: {manifest.unsupported_reason}"
            )

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        _read_pyproject(pyproject, result)

    setup_cfg = root / "setup.cfg"
    if setup_cfg.is_file():
        _read_setup_cfg(setup_cfg, result)

    for path in files:
        if path.name.casefold() in _UNSUPPORTED_LOCKFILES:
            relative = _relative(root, path)
            result.unsupported_files.append(relative)
            result.warnings.append(
                f"{relative} was found but is not supported for scanning in this version."
            )
        elif path.name.casefold() in _UNSUPPORTED_PROJECT_FILES:
            relative = _relative(root, path)
            result.unsupported_files.append(relative)
            result.warnings.append(
                f"{relative} may declare Python dependencies, but its format is not supported and was not scanned."
            )

    python_version_file = root / ".python-version"
    if python_version_file.is_file():
        try:
            values = [
                line.strip()
                for line in python_version_file.read_text(encoding="utf-8-sig").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]
            if len(values) != 1:
                raise ValueError("Expected exactly one Python target version.")
            value = values[0]
            result.python_target = _normalize_python_version(value)
            result.python_target_source = ".python-version"
            result.python_target_confidence = "declared"
        except (OSError, UnicodeError, IndexError, ValueError):
            result.warnings.append(".python-version could not be parsed.")
    if not result.python_target and result.requires_python:
        exact = _exact_python_version(result.requires_python)
        if exact:
            result.python_target = exact
            result.python_target_source = "requires-python metadata"
            result.python_target_confidence = "declared"
        else:
            result.python_target_source = "requires-python metadata"
            result.python_target_confidence = "range"
    if result.python_target and result.requires_python:
        try:
            if not SpecifierSet(result.requires_python).contains(Version(result.python_target)):
                result.python_target_conflict = True
                result.warnings.append(
                    f"Python target {result.python_target} conflicts with requires-python {result.requires_python}."
                )
        except (InvalidSpecifier, InvalidVersion):
            result.python_target_conflict = True
            result.warnings.append("Project requires-python metadata is invalid.")
    if not result.requires_python and result.python_target:
        result.requires_python = result.python_target
    return result


def _walk_files(root: Path) -> list[Path]:
    result = []
    for directory, names, filenames in os.walk(root):
        names[:] = sorted(name for name in names if name.casefold() not in _EXCLUDED_DIRS)
        base = Path(directory)
        result.extend(base / filename for filename in filenames)
    return result


def _read_pyproject(path: Path, result: ProjectDiscovery) -> None:
    relative = _relative(result.root, path)
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        result.unsupported_files.append(relative)
        result.warnings.append(f"{relative} contains unreadable or invalid TOML and was not scanned.")
        return

    project = data.get("project")
    if isinstance(project, dict):
        tool = data.get("tool", {})
        poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
        uv = tool.get("uv", {}) if isinstance(tool, dict) else {}
        pdm = tool.get("pdm", {}) if isinstance(tool, dict) else {}
        if "dependency-groups" in data:
            result.unsupported_files.append(relative)
            result.warnings.append(
                f"{relative} declares dependency-groups that are not supported yet."
            )
        if isinstance(poetry, dict) and any(
            key in poetry for key in ("dependencies", "group", "dev-dependencies", "source")
        ):
            result.unsupported_files.append(relative)
            result.warnings.append(
                f"{relative} declares Poetry dependency groups that are not supported yet."
            )
        if isinstance(uv, dict) and any(
            key in uv for key in ("sources", "index", "dev-dependencies", "dependency-groups")
        ):
            result.unsupported_files.append(relative)
            result.warnings.append(
                f"{relative} declares uv dependency sources or groups that are not supported yet."
            )
        if isinstance(pdm, dict) and any(key in pdm for key in ("source", "dev-dependencies", "dependency-groups")):
            result.unsupported_files.append(relative)
            result.warnings.append(
                f"{relative} declares PDM dependency sources or groups that are not supported yet."
            )
        requires_python = project.get("requires-python", "")
        if isinstance(requires_python, str) and requires_python:
            result.requires_python = requires_python
        dynamic = project.get("dynamic", [])
        dependencies = project.get("dependencies", [])
        if "dependencies" in dynamic or "optional-dependencies" in dynamic:
            result.unsupported_files.append(relative)
            result.warnings.append(
                f"{relative} declares dynamic dependency metadata; it cannot be resolved safely from static metadata."
            )
            return
        if not isinstance(dependencies, list) or any(not isinstance(item, str) for item in dependencies):
            result.unsupported_files.append(relative)
            result.warnings.append(f"{relative} has an unsupported PEP 621 dependencies value.")
            return
        optional = project.get("optional-dependencies", {})
        if not isinstance(optional, dict) or any(
            not isinstance(name, str) or not isinstance(values, list)
            or any(not isinstance(value, str) for value in values)
            for name, values in optional.items()
        ):
            result.unsupported_files.append(relative)
            result.warnings.append(f"{relative} has an unsupported optional-dependencies value.")
            return
        groups = [("main", list(dependencies))]
        groups.extend((f"extra:{name}", [*dependencies, *values]) for name, values in sorted(optional.items()))
        for group, values in groups:
            manifest = DependencyManifest(
                path=path, format="pyproject", group=group, display_path=relative
            )
            _add_pep508_dependencies(values, manifest, result.root)
            result.manifests.append(manifest)
            if manifest.unsupported_reason:
                result.unsupported_files.append(relative)
                result.warnings.append(
                    f"{relative}[{group}] was not scanned: {manifest.unsupported_reason}"
                )
        return

    if isinstance(data.get("tool"), dict) and "poetry" in data.get("tool", {}):
        result.unsupported_files.append(relative)
        result.warnings.append(
            f"{relative} uses Poetry metadata; only PEP 621 project dependencies are supported."
        )
    elif isinstance(data.get("tool"), dict) and "uv" in data.get("tool", {}):
        result.unsupported_files.append(relative)
        result.warnings.append(
            f"{relative} uses uv-specific metadata without PEP 621 dependencies; it was not scanned."
        )
    else:
        result.unsupported_files.append(relative)
        result.warnings.append(
            f"{relative} does not declare static PEP 621 dependencies and was not scanned."
        )


def _read_setup_cfg(path: Path, result: ProjectDiscovery) -> None:
    relative = _relative(result.root, path)
    parser = configparser.RawConfigParser(interpolation=None)
    try:
        parser.read(path, encoding="utf-8")
    except (OSError, UnicodeError, configparser.Error):
        result.unsupported_files.append(relative)
        result.warnings.append(f"{relative} could not be parsed and was not scanned.")
        return
    if not parser.has_section("options"):
        return
    requires_python = parser.get("options", "python_requires", fallback="").strip()
    if requires_python and not result.requires_python:
        result.requires_python = requires_python
    raw = parser.get("options", "install_requires", fallback="")
    dependencies = [line.strip() for line in raw.splitlines() if line.strip()]
    manifest = DependencyManifest(
        path=path, format="setup.cfg", group="main", display_path=relative
    )
    _add_pep508_dependencies(dependencies, manifest, result.root)
    result.manifests.append(manifest)
    if manifest.unsupported_reason:
        result.unsupported_files.append(relative)
        result.warnings.append(f"{relative} was not scanned: {manifest.unsupported_reason}")
    if parser.has_section("options.extras_require"):
        result.unsupported_files.append(relative)
        result.warnings.append(
            f"{relative} declares setup.cfg extras_require; those optional groups are not supported yet."
        )


def _add_pep508_dependencies(values: list[str], manifest: DependencyManifest, root: Path) -> None:
    for value in values:
        try:
            requirement = Requirement(value)
        except InvalidRequirement:
            manifest.unsupported_reason = "a dependency is not valid PEP 508 syntax."
            manifest.requirements.clear()
            manifest.direct_dependencies.clear()
            return
        if requirement.url:
            manifest.unsupported_reason = (
                "direct URL, VCS, or local dependencies are not fetched automatically."
            )
            manifest.requirements.clear()
            manifest.direct_dependencies.clear()
            return
        manifest.requirements.append(value)
        manifest.direct_dependencies.append({
            "name": requirement.name,
            "canonical_name": canonicalize_name(requirement.name),
            "specifier": str(requirement.specifier),
            "marker": str(requirement.marker) if requirement.marker else "",
            "extras": ",".join(sorted(requirement.extras)),
            "direct": True,
            "source_file": _relative(root, manifest.path),
        })


def _inspect_requirements(path: Path, root: Path, manifest: DependencyManifest) -> None:
    visited: set[Path] = set()
    active: set[Path] = set()
    direct: list[dict[str, str | bool]] = []
    included: list[Path] = []
    reason = _inspect_requirements_file(path.resolve(), root, visited, active, direct, included, constraint=False)
    manifest.direct_dependencies = direct
    manifest.included_files = included
    manifest.unsupported_reason = reason


def _inspect_requirements_file(
    path: Path,
    root: Path,
    visited: set[Path],
    active: set[Path],
    direct: list[dict[str, str | bool]],
    included: list[Path],
    *,
    constraint: bool,
) -> str:
    try:
        path.relative_to(root)
    except ValueError:
        return "an included requirements file resolves outside the project directory."
    if path in active:
        return "requirements includes form a cycle."
    if path in visited:
        return ""
    if len(visited) >= 100:
        return "requirements include limit was exceeded."
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeError):
        return "a requirements file is unreadable."
    visited.add(path)
    active.add(path)
    pending = ""
    for original in lines:
        raw = original.strip()
        if not raw or raw.startswith("#"):
            continue
        if raw.endswith("\\"):
            pending += raw[:-1] + " "
            continue
        line = pending + raw
        pending = ""
        line = line.split(" #", 1)[0].strip()
        if not line:
            continue
        include = _include_argument(line)
        if include:
            include_path, child_is_constraint = include
            resolved = (path.parent / include_path).resolve()
            included.append(resolved)
            reason = _inspect_requirements_file(
                resolved, root, visited, active, direct, included,
                constraint=constraint or child_is_constraint,
            )
            if reason:
                active.remove(path)
                return reason
            continue
        if line.startswith("-"):
            if line.startswith("--hash=") or line.startswith("--hash "):
                continue
            active.remove(path)
            return "a pip option other than -r/-c/--hash requires manual review."
        line = re.sub(r"\s+--hash(?:=|\s+)\S+", "", line)
        try:
            requirement = Requirement(line)
        except InvalidRequirement:
            active.remove(path)
            return "a requirement is not valid PEP 508 syntax."
        if requirement.url:
            active.remove(path)
            return "direct URL, VCS, or local dependencies are not fetched automatically."
        if not constraint:
            direct.append({
                "name": requirement.name,
                "canonical_name": canonicalize_name(requirement.name),
                "specifier": str(requirement.specifier),
                "marker": str(requirement.marker) if requirement.marker else "",
                "extras": ",".join(sorted(requirement.extras)),
                "direct": True,
                "source_file": _relative(root, path),
            })
    if pending:
        active.remove(path)
        return "a requirements continuation is incomplete."
    active.remove(path)
    return ""


def _include_argument(line: str) -> tuple[str, bool] | None:
    try:
        parts = shlex.split(line, posix=False)
    except ValueError:
        return None
    if not parts:
        return None
    token = parts[0]
    is_constraint = token in {"-c", "--constraint"} or token.startswith("-c") and token != "-c"
    is_requirement = token in {"-r", "--requirement"} or token.startswith("-r") and token != "-r"
    if not (is_constraint or is_requirement):
        if token.startswith("--constraint="):
            return token.split("=", 1)[1], True
        if token.startswith("--requirement="):
            return token.split("=", 1)[1], False
        return None
    if token in {"-c", "--constraint", "-r", "--requirement"}:
        if len(parts) != 2:
            return None
        return parts[1], is_constraint
    if token.startswith("--constraint=") or token.startswith("--requirement="):
        return token.split("=", 1)[1], is_constraint
    return token[2:], is_constraint


def _normalize_python_version(value: str) -> str:
    version = Version(value)
    if (
        len(version.release) not in {2, 3}
        or version.is_prerelease
        or version.is_devrelease
        or version.local is not None
    ):
        raise ValueError("Expected a stable major.minor or major.minor.micro Python version.")
    return str(version)


def _exact_python_version(requires_python: str) -> str:
    try:
        specifier_set = SpecifierSet(requires_python)
    except InvalidSpecifier:
        return ""
    specifiers = list(specifier_set)
    if len(specifiers) != 1 or specifiers[0].operator not in {"==", "==="}:
        return ""
    value = specifiers[0].version
    if "*" in value:
        return ""
    try:
        return _normalize_python_version(value)
    except (InvalidVersion, ValueError):
        return ""


def _relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return "<outside-project>"
