from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..evidence_export import build_evidence_export


SPDX_VERSION = "SPDX-3.0"


def _checksum_for_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def export_spdx(report_path: Path, output_path: Path) -> None:
    """Produce an enriched SPDX 3.0 JSON document from an inspector report.

    Adds richer package fields, file checksums, relationships, and references.
    """
    report = json.loads(report_path.read_text())
    evidence = build_evidence_export(report, report_path)

    doc: dict[str, Any] = {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": Path(evidence.report_path).name,
        "documentNamespace": f"urn:spdx:ai-bom-inspector:{Path(evidence.report_path).stem}",
        "creationInfo": {"created": evidence.generated_at, "creators": ["Tool: AI-BOM-Inspector"]},
        "packages": [],
        "files": [],
        "relationships": [],
    }

    # Map packages
    for dep in report.get("dependencies", []):
        pkg_name = dep.get("name") or dep.get("package") or dep.get("id") or "unknown"
        spdxid = f"SPDXRef-Package-{pkg_name.replace(' ', '_')}-{dep.get('version') or 'v0'}"
        pkg: dict[str, Any] = {
            "SPDXID": spdxid,
            "name": pkg_name,
            "versionInfo": dep.get("version"),
            "downloadLocation": dep.get("purl") or "NOASSERTION",
            "licenseConcluded": dep.get("license") or dep.get("licenses") or "NOASSERTION",
        }
        if dep.get("hashes"):
            pkg["checksums"] = dep.get("hashes")
        doc["packages"].append({k: v for k, v in pkg.items() if v is not None})

    # Map files (if model artifacts or checksum evidence present)
    for f in report.get("files", []):
        content = f.get("path") or f.get("name") or ""
        file_entry = {
            "SPDXID": f"SPDXRef-File-{_checksum_for_text(content)[:12]}",
            "fileName": content,
            "checksums": [{"algorithm": "SHA256", "checksumValue": _checksum_for_text(content)}],
            "licenseConcluded": f.get("license") or "NOASSERTION",
        }
        doc["files"].append(file_entry)

    # Relationships: package -> file or package -> package (dependsOn)
    for dep in report.get("dependencies", []):
        src = f"SPDXRef-Package-{(dep.get('name') or dep.get('package') or dep.get('id') or 'unknown').replace(' ', '_')}-{(dep.get('version') or 'v0')}"
        for d in dep.get("depends_on", []):
            target = f"SPDXRef-Package-{d.replace(' ', '_')}-v0"
            doc["relationships"].append({"spdxElementId": src, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": target})

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(doc, indent=2))


def export_spdx_tagvalue(report_path: Path, tv_output_path: Path) -> None:
    """Produce an SPDX tag-value document (human readable) from the report.

    Note: This is a conservative tag-value generator intended for PR comments
    and human consumption. It aims to include core fields and package list.
    """
    report = json.loads(report_path.read_text())
    evidence = build_evidence_export(report, report_path)

    lines = []
    lines.append(f"SPDXVersion: {SPDX_VERSION}")
    lines.append(f"DataLicense: CC0-1.0")
    lines.append(f"SPDXID: SPDXRef-DOCUMENT")
    lines.append(f"DocumentName: {Path(evidence.report_path).name}")
    lines.append(f"DocumentNamespace: urn:spdx:ai-bom-inspector:{Path(evidence.report_path).stem}")
    lines.append(f"Creator: Tool: AI-BOM-Inspector")
    lines.append(f"Created: {evidence.generated_at}")
    lines.append("")

    # Packages
    for dep in report.get("dependencies", []):
        name = dep.get("name") or dep.get("package") or dep.get("id") or "unknown"
        lines.append(f"PackageName: {name}")
        if dep.get("version"):
            lines.append(f"PackageVersion: {dep.get('version')}")
        lines.append(f"PackageDownloadLocation: {dep.get('purl') or 'NOASSERTION'}")
        if dep.get("licenses"):
            for lic in dep.get("licenses"):
                lines.append(f"PackageLicenseConcluded: {lic}")
        lines.append("")

    tv_output_path.parent.mkdir(parents=True, exist_ok=True)
    tv_output_path.write_text("\n".join(lines))
