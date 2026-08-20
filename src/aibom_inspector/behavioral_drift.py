from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .js_analysis import JSAnalysis, scan_javascript


@dataclass(frozen=True)
class DriftChange:
    change_type: str
    severity: str
    source: str | None
    relationship: str | None
    target: str | None
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_type": self.change_type,
            "severity": self.severity,
            "source": self.source,
            "relationship": self.relationship,
            "target": self.target,
            "reason": self.reason,
        }


def _edge_key(edge: dict[str, str]) -> tuple[str, str, str]:
    return edge["source"], edge["relationship"], edge["target"]


def compare_analyses(baseline: JSAnalysis, candidate: JSAnalysis) -> dict[str, Any]:
    old_edges = {_edge_key(e) for e in baseline.edges}
    new_edges = {_edge_key(e) for e in candidate.edges}
    old_findings = {(f.file, f.line, f.detector_id, f.symbol) for f in baseline.findings}
    new_findings = {(f.file, f.line, f.detector_id, f.symbol) for f in candidate.findings}

    changes: list[DriftChange] = []
    for source, relationship, target in sorted(new_edges - old_edges):
        severity = "critical" if relationship == "CAN_REACH" and ":input:" in source else "high"
        reason = "A new evidence-backed relationship makes a previously absent path reachable."
        changes.append(DriftChange("edge_added", severity, source, relationship, target, reason))
    for source, relationship, target in sorted(old_edges - new_edges):
        changes.append(DriftChange("edge_removed", "info", source, relationship, target, "A previously observed relationship is no longer present."))

    for file, line, detector_id, symbol in sorted(new_findings - old_findings):
        severity = "medium"
        if detector_id.startswith("JS-TAINT"):
            severity = "high"
        elif detector_id.startswith("JS-TOOL"):
            severity = "high"
        changes.append(DriftChange("finding_added", severity, f"{file}:{line}", detector_id, symbol, "A new AI/security behavior was discovered."))

    return {
        "schema_version": "behavioral-drift.v1",
        "baseline_files": baseline.files_scanned,
        "candidate_files": candidate.files_scanned,
        "edges_added": sum(1 for c in changes if c.change_type == "edge_added"),
        "edges_removed": sum(1 for c in changes if c.change_type == "edge_removed"),
        "findings_added": sum(1 for c in changes if c.change_type == "finding_added"),
        "impact_path_added": any(c.change_type == "edge_added" and c.relationship == "CAN_REACH" for c in changes),
        "changes": [c.to_dict() for c in changes],
    }


def load_analysis(path: str | Path) -> JSAnalysis:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return JSAnalysis(
        files_scanned=int(payload.get("files_scanned", 0)),
        findings=tuple(_finding_from_json(item) for item in payload.get("findings", [])),
        nodes=tuple(payload.get("nodes", [])),
        edges=tuple(payload.get("edges", [])),
    )


def _finding_from_json(item: dict[str, Any]):
    from .js_analysis import JSEvidence
    return JSEvidence(
        detector_id=str(item["detector_id"]),
        kind=str(item["kind"]),
        file=str(item["file"]),
        line=int(item["line"]),
        symbol=str(item["symbol"]),
        evidence=str(item.get("evidence", "")),
        confidence=float(item.get("confidence", 0.0)),
        role=item.get("role"),
    )


def scan_and_compare(baseline_path: str | Path, candidate_path: str | Path) -> dict[str, Any]:
    baseline = scan_javascript(baseline_path)
    candidate = scan_javascript(candidate_path)
    return compare_analyses(baseline, candidate)
