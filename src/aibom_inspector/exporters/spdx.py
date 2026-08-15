from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..evidence_export import build_evidence_export


SPDX_VERSION = "SPDX-3.0"


def export_spdx(report_path: Path, output_path: Path) -> None:
    """Produce a minimal SPDX 3.0 JSON document from an inspector report.

    This exporter provides a basic mapping for packages and files; extend as
    needed for full license and snippet coverage.
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
    }

    for dep in report.get("dependencies", []):
        pkg = {
            "SPDXID": f"SPDXRef-Package-{(dep.get('name') or dep.get('id') or 'unknown').replace(' ', '_')}",
            "name": dep.get("name") or dep.get("package") or dep.get("id"),
            "versionInfo": dep.get("version"),
            "downloadLocation": dep.get("purl") or "NOASSERTION",
            "licenseConcluded": dep.get("license") or "NOASSERTION",
        }
        pkg = {k: v for k, v in pkg.items() if v is not None}
        doc["packages"].append(pkg)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(doc, indent=2))
