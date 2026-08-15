from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..evidence_export import build_evidence_export


SPEC_VERSION = "1.7"


def export_cyclonedx(report_path: Path, output_path: Path) -> None:
    """Produce a minimal CycloneDX 1.7 BOM JSON from an inspector report.

    This is a canonical exporter skeleton — extend mapping rules to include
    full component metadata, dependencies, and externalReferences as needed.
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
            "authors": [],
            "component": {
                "type": "application",
                "name": Path(evidence.report_path).name,
                "description": evidence.summary.get("executive_summary"),
            },
        },
        "components": [],
    }

    # Map dependencies section (best-effort). Expect report.get('dependencies') to be list of dicts
    for dep in report.get("dependencies", []):
        comp = {
            "type": dep.get("type", "library"),
            "name": dep.get("name") or dep.get("package") or dep.get("id"),
            "version": dep.get("version"),
            "purl": dep.get("purl"),
            "licenses": [{"license": {"name": l}} for l in (dep.get("licenses") or [])],
        }
        # prune None values
        comp = {k: v for k, v in comp.items() if v}
        bom["components"].append(comp)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(bom, indent=2))
