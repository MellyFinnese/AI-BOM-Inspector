from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Iterable, List

from .types import DependencyInfo, DependencyIssue


PINNED_PATTERN = re.compile(r"(?P<name>[A-Za-z0-9_.-]+)(?P<specifier>==|>=|<=|~=|!=|>|<)?(?P<version>.+)?")


def parse_requirement_line(line: str) -> DependencyInfo | None:
    cleaned = line.strip()
    if not cleaned or cleaned.startswith("#"):
        return None

    match = PINNED_PATTERN.match(cleaned)
    if not match:
        return DependencyInfo(name=cleaned, version=None, source="requirements.txt", issues=[])

    name = match.group("name")
    specifier = match.group("specifier") or ""
    version = match.group("version").strip() if match.group("version") else None
    issues: List[DependencyIssue] = []

    if not version:
        issues.append(DependencyIssue("Unpinned dependency", severity="high"))
    elif specifier not in {"==", "~="}:
        issues.append(DependencyIssue("Version is not strictly pinned", severity="medium"))

    if version and version.startswith("0."):
        issues.append(DependencyIssue("Pre-1.0 release may be unstable", severity="medium"))

    return DependencyInfo(name=name, version=f"{specifier}{version}" if specifier else version, source="requirements.txt", issues=issues)


def scan_requirements(path: Path) -> List[DependencyInfo]:
    if not path.exists():
        return []

    dependencies: List[DependencyInfo] = []
    for line in path.read_text().splitlines():
        info = parse_requirement_line(line)
        if info:
            dependencies.append(info)
    return dependencies


def scan_pyproject(path: Path) -> List[DependencyInfo]:
    if not path.exists():
        return []

    data = tomllib.loads(path.read_text())
    project = data.get("project", {})
    dependencies: List[DependencyInfo] = []

    def _from_iterable(values: Iterable[str]) -> None:
        for raw in values:
            info = parse_requirement_line(raw)
            if info:
                info.source = "pyproject.toml"
                dependencies.append(info)

    _from_iterable(project.get("dependencies", []))
    optional = project.get("optional-dependencies", {}) or {}
    for extra in optional.values():
        _from_iterable(extra)

    return dependencies


def summarize_dependencies(paths: Iterable[Path]) -> List[DependencyInfo]:
    dependencies: List[DependencyInfo] = []
    for path in paths:
        if path.name == "requirements.txt":
            dependencies.extend(scan_requirements(path))
        elif path.name == "pyproject.toml":
            dependencies.extend(scan_pyproject(path))
    return dependencies
