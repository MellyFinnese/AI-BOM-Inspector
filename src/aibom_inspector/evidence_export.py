from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass(frozen=True)
class EvidenceExport:
    generated_at: str
    report_path: str
    summary: dict
    provenance: dict | None
    integrity_findings: list[dict]
    approvals: list[str]
    framework_mappings: dict


def _collect_frameworks(report: dict) -> dict:
    frameworks: dict[str, set[str]] = {}
    for section in ("dependencies", "models"):
        for entry in report.get(section, []):
            for detail in entry.get("issue_details", []):
                for mapping in detail.get("frameworks", []) or []:
                    framework = mapping.get("framework")
                    control = mapping.get("control")
                    if not framework or not control:
                        continue
                    frameworks.setdefault(framework, set()).add(control)
    return {name: sorted(controls) for name, controls in frameworks.items()}


def build_evidence_export(report: dict, report_path: Path) -> EvidenceExport:
    summary = {
        "stack_risk_score": report.get("stack_risk_score"),
        "risk_breakdown": report.get("risk_breakdown"),
        "executive_summary": report.get("executive_summary"),
    }
    return EvidenceExport(
        generated_at=datetime.utcnow().isoformat(),
        report_path=str(report_path),
        summary=summary,
        provenance=report.get("provenance"),
        integrity_findings=report.get("integrity_findings", []),
        approvals=report.get("approvals", []) or [],
        framework_mappings=_collect_frameworks(report),
    )


def write_evidence_export(report_path: Path, output_path: Path) -> None:
    report_payload = json.loads(report_path.read_text())
    evidence = build_evidence_export(report_payload, report_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(evidence.__dict__, indent=2))
