from dataclasses import dataclass
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version


@dataclass
class RequirementsInput:
    path: Path
    lines: list[str]
    requirements: list[tuple[int, Requirement]]
    unsupported_reason: str = ""


def read_requirements(path: Path) -> RequirementsInput:
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    parsed = []
    for index, original in enumerate(lines):
        line = original.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\") or line.startswith("-"):
            return RequirementsInput(path, lines, parsed,
                                     "Includes, pip options and continuations require manual review.")
        value = line.split(" #", 1)[0].strip()
        try:
            requirement = Requirement(value)
        except InvalidRequirement:
            return RequirementsInput(path, lines, parsed,
                                     f"Unsupported requirement syntax on line {index + 1}.")
        if requirement.url:
            return RequirementsInput(path, lines, parsed,
                                     "Direct URL, VCS and local dependencies are not queried or rewritten.")
        parsed.append((index, requirement))
    return RequirementsInput(path, lines, parsed)


def rewrite_for_candidates(
    source: RequirementsInput,
    candidates: dict[str, str],
) -> list[str]:
    output = list(source.lines)
    rewritten = set()
    for index, requirement in source.requirements:
        name = canonicalize_name(requirement.name)
        candidate = candidates.get(name)
        if candidate is None:
            continue
        extras = f"[{','.join(sorted(requirement.extras))}]" if requirement.extras else ""
        marker = f"; {requirement.marker}" if requirement.marker else ""
        output[index] = f"{requirement.name}{extras}=={Version(candidate)}{marker}"
        rewritten.add(name)
    for name, candidate in candidates.items():
        if name not in rewritten:
            output.append(f"{name}=={Version(candidate)}")
    return output
