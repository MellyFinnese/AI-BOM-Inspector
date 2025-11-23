from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable, List

try:  # Python < 3.11 compatibility
    import tomllib  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - exercised in older runtimes
    import tomli as tomllib  # type: ignore

from packaging.requirements import Requirement

from .types import (
    DependencyInfo,
    DependencyIssue,
    apply_license_category_dependency,
)


KNOWN_BAD_VERSIONS = {
    "urllib3": {
        "1.25.8": {
            "issue": "CVE-2019-11324: CRLF injection when retrieving HTTP headers",
            "upgrade_to": ">=1.25.9",
        },
        "1.26.0": {
            "issue": "CVE-2020-26137: CRLF injection via HTTP request headers",
            "upgrade_to": ">=1.26.2",
        },
    },
    "transformers": {
        "4.37.0": {
            "issue": "Known unsafe deserialization issue in pipeline loading",
            "upgrade_to": ">=4.37.1",
        },
    },
}


def _issue_for_specifier(specifier: str | None, version: str | None) -> list[DependencyIssue]:
    issues: list[DependencyIssue] = []
    if not version:
        issues.append(DependencyIssue("[MISSING_PIN] Dependency is not pinned", severity="high"))
    elif specifier not in {"==", "~="}:
        issues.append(DependencyIssue("[LOOSE_PIN] Version is not strictly pinned", severity="medium"))

    if version and version.startswith("0."):
        issues.append(DependencyIssue("[UNSTABLE_VERSION] Pre-1.0 release may be unstable", severity="medium"))

    return issues
def parse_requirement_line(line: str, source: str = "requirements.txt") -> DependencyInfo | None:
    cleaned = line.strip()
    if not cleaned or cleaned.startswith("#"):
        return None

    try:
        req = Requirement(cleaned)
    except Exception:
        return DependencyInfo(name=cleaned, version=None, source=source, issues=[])

    specifier = None
    version = None
    if req.specifier:
        first_spec = next(iter(req.specifier))
        specifier = first_spec.operator
        version = first_spec.version

    issues = _issue_for_specifier(specifier, version)

    if req.url:
        issues.append(
            DependencyIssue(
                "[UNVERIFIED_SOURCE] Direct URL requirement; verify integrity", severity="medium"
            )
        )

    vuln_versions = KNOWN_BAD_VERSIONS.get(req.name.lower()) or KNOWN_BAD_VERSIONS.get(req.name)
    if specifier == "==" and version and vuln_versions and version in vuln_versions:
        details = vuln_versions[version]
        suggestion = f"; upgrade to {details['upgrade_to']}" if details.get("upgrade_to") else ""
        issues.append(
            DependencyIssue(
                f"[KNOWN_VULN] {details['issue']}{suggestion}",
                severity="high",
            )
        )

    resolved_version = str(req.specifier) if req.specifier else version

    dep = DependencyInfo(name=req.name, version=resolved_version, source=source, issues=issues)
    apply_license_category_dependency(dep)
    return dep


def scan_requirements(path: Path) -> List[DependencyInfo]:
    if not path.exists():
        return []

    dependencies: List[DependencyInfo] = []
    for line in path.read_text().splitlines():
        info = parse_requirement_line(line, source="requirements.txt")
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
            info = parse_requirement_line(raw, source="pyproject.toml")
            if info:
                dependencies.append(info)

    _from_iterable(project.get("dependencies", []))
    optional = project.get("optional-dependencies", {}) or {}
    for extra in optional.values():
        _from_iterable(extra)

    return dependencies


def scan_package_json(path: Path) -> List[DependencyInfo]:
    if not path.exists():
        return []

    data = json.loads(path.read_text())
    dependencies: List[DependencyInfo] = []

    def _parse_block(block: dict | None) -> None:
        if not block:
            return
        for name, version in block.items():
            specifier = None
            version_value = str(version)
            if version_value.startswith("^") or version_value.startswith("~"):
                specifier = version_value[0]
                version_clean = version_value[1:]
            else:
                version_clean = version_value
            issues = _issue_for_specifier(specifier if specifier else "==", version_clean)
            dep = DependencyInfo(
                name=name,
                version=version_value,
                source="package.json",
                issues=issues,
            )
            apply_license_category_dependency(dep)
            dependencies.append(dep)

    _parse_block(data.get("dependencies"))
    _parse_block(data.get("devDependencies"))
    return dependencies


def scan_package_lock(path: Path) -> List[DependencyInfo]:
    if not path.exists():
        return []

    data = json.loads(path.read_text())
    deps: List[DependencyInfo] = []
    packages = data.get("packages") or {}
    for name, details in packages.items():
        if name == "":
            continue
        version = details.get("version")
        issues = _issue_for_specifier("==", version)
        dep = DependencyInfo(
            name=name.lstrip("./"),
            version=version,
            source="package-lock.json",
            issues=issues,
        )
        apply_license_category_dependency(dep)
        deps.append(dep)
    return deps


def scan_go_mod(path: Path) -> List[DependencyInfo]:
    if not path.exists():
        return []

    dependencies: List[DependencyInfo] = []
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("require") and "(" in stripped:
            continue
        if stripped.startswith("//") or not stripped:
            continue
        if stripped.startswith("module") or stripped.startswith("go "):
            continue
        if stripped.startswith("require"):
            stripped = stripped.replace("require", "", 1).strip()
        if " " in stripped:
            name, version = stripped.split(None, 1)
            issues = _issue_for_specifier("==", version)
            dep = DependencyInfo(name=name, version=version, source="go.mod", issues=issues)
            apply_license_category_dependency(dep)
            dependencies.append(dep)
    return dependencies


def scan_pom(path: Path) -> List[DependencyInfo]:
    if not path.exists():
        return []

    content = path.read_text()
    dependency_blocks = re.findall(r"<dependency>(.*?)</dependency>", content, flags=re.DOTALL)
    deps: List[DependencyInfo] = []
    for block in dependency_blocks:
        group_id = re.search(r"<groupId>(.*?)</groupId>", block)
        artifact_id = re.search(r"<artifactId>(.*?)</artifactId>", block)
        version = re.search(r"<version>(.*?)</version>", block)
        if not (artifact_id and group_id):
            continue
        name = f"{group_id.group(1)}:{artifact_id.group(1)}"
        version_value = version.group(1).strip() if version else None
        issues = _issue_for_specifier("==" if version_value else None, version_value)
        dep = DependencyInfo(
            name=name, version=version_value, source="pom.xml", issues=issues
        )
        apply_license_category_dependency(dep)
        deps.append(dep)
    return deps


def summarize_dependencies(paths: Iterable[Path]) -> List[DependencyInfo]:
    dependencies: List[DependencyInfo] = []
    for path in paths:
        if path.name == "requirements.txt":
            dependencies.extend(scan_requirements(path))
        elif path.name == "pyproject.toml":
            dependencies.extend(scan_pyproject(path))
        elif path.name == "package.json":
            dependencies.extend(scan_package_json(path))
        elif path.name == "package-lock.json":
            dependencies.extend(scan_package_lock(path))
        elif path.name == "go.mod":
            dependencies.extend(scan_go_mod(path))
        elif path.name == "pom.xml":
            dependencies.extend(scan_pom(path))
    return dependencies


def normalize_version(version: str | None) -> str:
    if not version:
        return ""
    cleaned = version.lstrip("=<>~^!").strip()
    # For Maven style versions, just return raw
    return cleaned


def enrich_with_osv(dependencies: List[DependencyInfo], offline: bool = False) -> List[DependencyInfo]:
    """Optionally enrich dependencies with OSV CVE lookups."""

    ecosystem_map = {
        "requirements.txt": "PyPI",
        "pyproject.toml": "PyPI",
        "package.json": "npm",
        "package-lock.json": "npm",
        "go.mod": "Go",
        "pom.xml": "Maven",
        "cyclonedx": "PyPI",
        "spdx": "PyPI",
    }

    for dep in dependencies:
        if offline:
            dep.issues.append(
                DependencyIssue(
                    "[CVE_LOOKUP_SKIPPED] Offline mode enabled; skipping OSV",
                    severity="low",
                )
            )
            continue
        version = normalize_version(dep.version)
        ecosystem = ecosystem_map.get(dep.source, "PyPI")
        if not version:
            continue
        payload = {"package": {"name": dep.name, "ecosystem": ecosystem}, "version": version}
        try:
            import requests  # type: ignore

            response = requests.post("https://api.osv.dev/v1/query", json=payload, timeout=8)
            if response.status_code != 200:
                dep.issues.append(
                    DependencyIssue(
                        "[CVE_LOOKUP_FAILED] OSV request did not return results",
                        severity="low",
                    )
                )
                continue
            data = response.json()
            for vuln in data.get("vulns", []) or []:
                vuln_id = vuln.get("id") or (vuln.get("aliases") or [None])[0] or "CVE"
                summary = vuln.get("summary") or "Vulnerability detected"
                dep.issues.append(
                    DependencyIssue(
                        f"[CVE] {vuln_id}: {summary}",
                        severity="high",
                        code=vuln_id,
                    )
                )
        except ImportError:
            dep.issues.append(
                DependencyIssue(
                    "[CVE_LOOKUP_SKIPPED] requests not installed; skipping OSV",
                    severity="low",
                )
            )
        except Exception:
            dep.issues.append(
                DependencyIssue(
                    "[CVE_LOOKUP_FAILED] Unable to reach OSV", severity="low"
                )
            )

    return dependencies


def parse_sbom(path: Path) -> List[DependencyInfo]:
    if not path.exists():
        return []

    data = json.loads(path.read_text())
    if str(data.get("bomFormat", "")).lower() == "cyclonedx":
        deps: list[DependencyInfo] = []
        for comp in data.get("components", []) or []:
            license_value = None
            licenses = comp.get("licenses") or []
            if licenses:
                license_data = licenses[0].get("license", {}) or {}
                license_value = license_data.get("id") or license_data.get("name")
            dep = DependencyInfo(
                name=comp.get("name", "unknown"),
                version=comp.get("version"),
                source="cyclonedx",
                license=license_value,
                issues=_issue_for_specifier("==", comp.get("version")),
            )
            apply_license_category_dependency(dep)
            deps.append(dep)
        return deps

    if data.get("spdxVersion"):
        deps = []
        for pkg in data.get("packages", []) or []:
            license_value = pkg.get("licenseDeclared") or pkg.get("licenseConcluded")
            dep = DependencyInfo(
                name=pkg.get("name", "unknown"),
                version=pkg.get("versionInfo"),
                source="spdx",
                license=license_value,
                issues=_issue_for_specifier("==", pkg.get("versionInfo")),
            )
            apply_license_category_dependency(dep)
            deps.append(dep)
        return deps

    return []
