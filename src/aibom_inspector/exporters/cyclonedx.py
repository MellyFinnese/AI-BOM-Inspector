from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..evidence_export import build_evidence_export


SPEC_VERSION = "1.7"


def _safe_bom_ref(name: str, version: str | None) -> str:
    key = f"{name}:{version or '0'}"
    # replace unsafe chars with underscore
    return re.sub(r"[^A-Za-z0-9_.:-]", "_", key)


def _map_license_list(licenses: list | None) -> list | None:
    if not licenses:
        return None
    return [{"license": {"name": l}} for l in licenses]


def export_cyclonedx(report_path: Path, output_path: Path) -> None:
    """Produce a more complete CycloneDX 1.7 BOM JSON from an inspector report.

    Maps components, basic dependency relationships, vulnerabilities (if present),
    and externalReferences. This is still a conservative mapping; extend as needed.
    """
    report = json.loads(report_path.read_text())
    evidence = build_evidence_export(report, report_path)

    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": evidence.generated_at,
            "tools": [{"vendor": "AI-BOM-Inspector", "name": "AI-BOM-Inspector", "version": "0.0.0"}],
            "component": {
                "type": "application",
                "name": Path(evidence.report_path).name,
                "description": evidence.summary.get("executive_summary"),
            },
        },
        "components": [],
        "dependencies": [],
    }

    # Build components and index by bom-ref
    comp_index: dict[str, dict] = {}
    for dep in report.get("dependencies", []):
        name = dep.get("name") or dep.get("package") or dep.get("id") or "unknown"
        version = dep.get("version")
        bom_ref = dep.get("bom-ref") or _safe_bom_ref(name, version)

        comp: dict[str, Any] = {
            "bom-ref": bom_ref,
            "type": dep.get("type", "library"),
            "name": name,
        }
        if version:
            comp["version"] = version
        if dep.get("purl"):
            comp.setdefault("externalReferences", []).append({"url": dep.get("purl"), "type": "purl"})
        if dep.get("external_references"):
            for r in dep.get("external_references"):
                comp.setdefault("externalReferences", []).append(r)
        if dep.get("hashes"):
            comp["hashes"] = dep.get("hashes")
        licenses = _map_license_list(dep.get("licenses") or ([dep.get("license")] if dep.get("license") else None))
        if licenses:
            comp["licenses"] = licenses

        comp_index[bom_ref] = comp
        bom["components"].append(comp)

    # Map simple dependency relationships if present in report
    # Expect report.dependencies to optionally include 'depends_on' list of bom-refs or names
    for dep in report.get("dependencies", []):
        name = dep.get("name") or dep.get("package") or dep.get("id") or "unknown"
        version = dep.get("version")
        bom_ref = dep.get("bom-ref") or _safe_bom_ref(name, version)
        dep_entry = {"ref": bom_ref}
        depends_on = []
        for d in dep.get("depends_on", []):
            # allow either bom-ref or name/version mapping
            if d in comp_index:
                depends_on.append(d)
            else:
                # try to resolve by name or name:version
                candidate = _safe_bom_ref(d, None)
                if candidate in comp_index:
                    depends_on.append(candidate)
        if depends_on:
            dep_entry["dependsOn"] = depends_on
        bom["dependencies"].append(dep_entry)

    # Map vulnerabilities (best-effort)
    if report.get("vulnerabilities"):
        vulns = []
        for v in report.get("vulnerabilities", []):
            vuln = {"id": v.get("id") or v.get("cve") or v.get("name"), "ratings": v.get("ratings") or []}
            if v.get("references"):
                vuln["references"] = v.get("references")
            if v.get("affects"):
                # convert affected components into refs when possible
                affected = []
                for a in v.get("affects"):
                    if a in comp_index:
                        affected.append({"ref": a})
                    else:
                        # attempt to resolve by name
                        found = next((ref for ref, c in comp_index.items() if c.get("name") == a), None)
                        if found:
                            affected.append({"ref": found})
                if affected:
                    vuln["affects"] = affected
            vulns.append(vuln)
        if vulns:
            bom["vulnerabilities"] = vulns

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(bom, indent=2))
