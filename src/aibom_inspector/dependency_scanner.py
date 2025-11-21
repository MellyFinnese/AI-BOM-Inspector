from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Iterable, List

import tomllib

from .types import DependencyInfo, DependencyIssue


PINNED_PATTERN = re.compile(r"(?P<name>[A-Za-z0-9_.-]+)(?P<specifier>==|>=|<=|~=|!=|>|<)?(?P<version>.+)?")


KNOWN_BAD_VERSIONS = {
    "urllib3": {
        "1.25.8": "CVE-2019-11324: CRLF injection when retrieving HTTP headers",
        "1.26.0": "CVE-2020-26137: CRLF injection via HTTP request headers",
    },
    "transformers": {
        "4.37.0": "Known unsafe deserialization issue in pipeline loading",
    },
}


def _query_osv(batch: list[dict]) -> list[dict]:
    """Send a batch query to OSV; resilient to offline CI."""

    try:
        import requests

        response = requests.post("https://api.osv.dev/v1/querybatch", json={"queries": batch}, timeout=10)
        if response.status_code == 200:
            return response.json().get("results", [])
    except Exception:
        return []
    return []


def enrich_with_osv(dependencies: List[DependencyInfo]) -> List[DependencyInfo]:
    """Add CVE issues from OSV when versions are pinned."""

    batch = []
    dep_lookup: list[DependencyInfo] = []
    for dep in dependencies:
        if dep.version and dep.version.startswith("=="):
            batch.append({"package": {"name": dep.name, "ecosystem": "PyPI"}, "version": dep.version.replace("==", "")})
            dep_lookup.append(dep)

    if not batch:
        return dependencies

    results = _query_osv(batch)
    for dep, res in zip(dep_lookup, results):
        vulns = res.get("vulns") or []
        for vuln in vulns:
            summary = vuln.get("summary") or vuln.get("id") or "OSV vulnerability"
            dep.issues.append(DependencyIssue(f"[CVE] {summary}", severity="high", code="CVE"))
    return dependencies


def run_pip_audit(requirements: Path | None) -> list[DependencyIssue]:
    if not requirements or not requirements.exists():
        return []

    try:
        result = subprocess.run([
            "pip-audit",
            "--requirement",
            str(requirements),
            "--format",
            "json",
        ], capture_output=True, text=True, check=False)
        if result.returncode not in {0, 1}:  # pip-audit returns 1 when vulns found
            return []
        data = json.loads(result.stdout or "{}")
    except Exception:
        return []

    issues: list[DependencyIssue] = []
    for item in data.get("dependencies", []):
        name = item.get("name")
        for vuln in item.get("vulns", []):
            if vuln.get("id"):
                issues.append(DependencyIssue(f"[CVE] {vuln['id']} detected for {name}", severity="high", code="CVE"))
    return issues


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
        issues.append(DependencyIssue("[MISSING_PIN] Dependency is not pinned", severity="high"))
    elif specifier not in {"==", "~="}:
        issues.append(DependencyIssue("[LOOSE_PIN] Version is not strictly pinned", severity="medium"))

    if version and version.startswith("0."):
        issues.append(DependencyIssue("[UNSTABLE_VERSION] Pre-1.0 release may be unstable", severity="medium"))

    resolved = f"{specifier}{version}" if specifier else version
    vuln_versions = KNOWN_BAD_VERSIONS.get(name.lower()) or KNOWN_BAD_VERSIONS.get(name)
    if specifier == "==" and version and vuln_versions:
        if version in vuln_versions:
            issues.append(
                DependencyIssue(
                    f"[KNOWN_VULN] {vuln_versions[version]}",
                    severity="high",
                )
            )

    return DependencyInfo(name=name, version=resolved, source="requirements.txt", issues=issues)


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


def parse_sbom_file(path: Path) -> List[DependencyInfo]:
    if not path.exists():
        return []

    data = json.loads(path.read_text())
    dependencies: List[DependencyInfo] = []

    for component in data.get("components", []):  # CycloneDX style
        name = component.get("name")
        version = component.get("version")
        if name:
            dependencies.append(DependencyInfo(name=name, version=version, source=str(path), issues=[]))

    for package in data.get("packages", []):  # SPDX style
        name = package.get("name")
        version = package.get("versionInfo") or package.get("version")
        if name:
            dependencies.append(DependencyInfo(name=name, version=version, source=str(path), issues=[]))

    return dependencies
