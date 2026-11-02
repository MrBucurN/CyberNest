"""Read-only PyPI release diagnostics for failed binary resolution."""

import json
import sys
import sysconfig
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.tags import compatible_tags, cpython_tags, parse_tag, sys_tags
from packaging.utils import parse_wheel_filename
from packaging.version import InvalidVersion, Version


TIMEOUT_SECONDS = 5


def inspect_release_payload(payload: object, python_version: str | None) -> dict[str, object]:
    if not isinstance(payload, dict) or not isinstance(payload.get("info"), dict):
        return {"status": "api_error", "release_exists": None}

    info = payload["info"]
    release_python = info.get("requires_python") or ""
    files = payload.get("urls")
    files = [item for item in files if isinstance(item, dict)] if isinstance(files, list) else []
    wheels = [
        item for item in files
        if item.get("packagetype") == "bdist_wheel" and not item.get("yanked", False)
    ]
    sdists = [
        item for item in files
        if item.get("packagetype") == "sdist" and not item.get("yanked", False)
    ]
    python_compatible = _python_compatible(release_python, python_version)
    supported_tags = _target_tags(python_version)
    matching_wheels = []
    if supported_tags is not None and python_compatible is not False:
        for item in wheels:
            filename = item.get("filename")
            if not isinstance(filename, str):
                continue
            try:
                _, _, _, wheel_tags = parse_wheel_filename(filename)
            except (InvalidVersion, ValueError):
                continue
            artifact_python = item.get("requires_python") or ""
            if _python_compatible(artifact_python, python_version) is False:
                continue
            if wheel_tags & supported_tags:
                matching_wheels.append(filename)

    return {
        "status": "available",
        "release_exists": True,
        "requires_python": release_python,
        "python_compatible": python_compatible,
        "any_wheel_available": bool(wheels),
        "target_wheel_available": (
            None if supported_tags is None else bool(matching_wheels)
        ),
        "source_archive_available": bool(sdists),
        "matching_wheels": matching_wheels,
        "url_count": len(files),
    }


def probe_pypi_release(name: str, version: str, python_version: str | None) -> dict[str, object]:
    url = f"https://pypi.org/pypi/{quote(name, safe='')}/{quote(version, safe='')}/json"
    request = Request(url, headers={
        "Accept": "application/json",
        "User-Agent": "CyberNest-resolver-diagnostics",
    })
    try:
        with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        error.close()
        if error.code == 404:
            return {
                "status": "not_found",
                "release_exists": False,
                "source": "PyPI JSON API",
                "url": url,
            }
        return {
            "status": "rate_limited" if error.code == 429 else "api_error",
            "release_exists": None,
            "source": "PyPI JSON API",
            "url": url,
            "http_status": error.code,
        }
    except (URLError, TimeoutError, OSError) as error:
        return {
            "status": "network_error",
            "release_exists": None,
            "source": "PyPI JSON API",
            "url": url,
            "error": type(error).__name__,
        }
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {
            "status": "api_error",
            "release_exists": None,
            "source": "PyPI JSON API",
            "url": url,
        }

    evidence = inspect_release_payload(payload, python_version)
    evidence.update({"source": "PyPI JSON API", "url": url})
    return evidence


def _python_compatible(requires_python: str, python_version: str | None) -> bool | None:
    if not python_version:
        return None
    if not requires_python:
        return True
    try:
        return SpecifierSet(requires_python).contains(Version(python_version))
    except (InvalidSpecifier, InvalidVersion):
        return None


def _target_tags(python_version: str | None):
    if not python_version:
        return None
    try:
        target = Version(python_version)
    except InvalidVersion:
        return None
    if len(target.release) < 2:
        return None
    target_pair = target.release[:2]
    if target_pair == (sys.version_info.major, sys.version_info.minor):
        return set(sys_tags())
    if sys.platform != "win32":
        # Cross-version wheel tags on other platforms require platform-specific
        # compatibility expansion; leave that judgment unknown.
        return None
    platform = sysconfig.get_platform().replace("-", "_")
    if platform == "win-amd64":
        platform = "win_amd64"
    elif platform == "win-arm64":
        platform = "win_arm64"
    interpreter = f"cp{target_pair[0]}{target_pair[1]}"
    tags = set(cpython_tags(
        python_version=target_pair,
        abis=(interpreter, "abi3", "none"),
        platforms=(platform,),
    ))
    tags.update(compatible_tags(
        python_version=target_pair,
        interpreter=interpreter,
        platforms=(platform,),
    ))
    # Some wheels are tagged for any Python version and platform-independent.
    tags.update(parse_tag("py3-none-any"))
    return tags
