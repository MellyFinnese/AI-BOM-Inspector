from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .attack_paths import discover_impact_paths
from .js_analysis import JSEvidence, JSAnalysis
from .js_semantics import semantic_scan_javascript


@dataclass(frozen=True)
class DriftChange:
    change_type: str
    severity: str
    source: str | None
    relationship: str | None
    target: str | None
    reason: str
    path: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_type": self.change_type,
            "severity": self.severity,
            "source": self.source,
            "relationship": self.relationship,
            "target": self.target,
            "reason": self.reason,
            "path": list(self.path),
        }


def _edge_key(edge: dict[str, str]) -> tuple[str, str, str]:
    return edge["source"], edge["relationship"], edge["target"]


def compare_analyses(baseline: JSAnalysis, candidate: JSAnalysis) -> dict[str, Any]:
    old_edges = {_edge_key(e) for e in baseline.edges}
    new_edges = {_edge_key(e) for e in candidate.edges}
    old_findings = {(f.file, f.line, f.detector_id, f.symbol) for f in baseline.findings}
    new_findings = {(f.file, f.line, f.detector_id, f.symbol) for f in candidate.findings}

    old_paths = discover_impact_paths(baseline)
    new_paths = discover_impact_paths(candidate)
    old_by_id = {path.path_id: path for path in old_paths}
    new_by_id = {path.path_id: path for path in new_paths}

    changes: list[DriftChange] = []
    for source, relationship, target in sorted(new_edges - old_edges):
        severity = "high" if relationship == "CAN_REACH" else "medium"
        changes.append(DriftChange("edge_added", severity, source, relationship, target, "A new evidence-backed relationship was introduced."))
    for source, relationship, target in sorted(old_edges - new_edges):
        changes.append(DriftChange("edge_removed", "info", source, relationship, target, "A previously observed relationship is no longer present."))

    for file, line, detector_id, symbol in sorted(new_findings - old_findings):
        severity = "high" if detector_id.startswith(("JS-TAINT", "JS-TOOL")) else "medium"
        changes.append(DriftChange("finding_added", severity, f"{file}:{line}", detector_id, symbol, "A new AI/security behavior was discovered."))

    added_paths = [new_by_id[key] for key in sorted(new_by_id.keys() - old_by_id.keys())]
    removed_paths = [old_by_id[key] for key in sorted(old_by_id.keys() - new_by_id.keys())]
    for path in added_paths:
        changes.append(
            DriftChange(
                "impact_path_added",
                path.severity,
                path.source,
                path.relationships[0] if path.relationships else None,
                path.target,
                "A previously absent input-to-side-effect path is now reachable in the evidence graph.",
                path.nodes,
            )
        )

    return {
        "schema_version": "behavioral-drift.v3",
        "baseline_files": baseline.files_scanned,
        "candidate_files": candidate.files_scanned,
        "edges_added": len(new_edges - old_edges),
        "edges_removed": len(old_edges - new_edges),
        "findings_added": len(new_findings - old_findings),
        "impact_paths_baseline": len(old_paths),
        "impact_paths_candidate": len(new_paths),
        "impact_paths_added": len(added_paths),
        "impact_paths_removed": len(removed_paths),
        "impact_path_added": bool(added_paths),
        "impact_severity": max((path.severity for path in added_paths), key={"medium": 1, "high": 2, "critical": 3}.get, default="none"),
        "impact_paths": [path.to_dict() for path in added_paths],
        "removed_impact_paths": [path.to_dict() for path in removed_paths],
        "changes": [change.to_dict() for change in changes],
    }


def load_analysis(path: str | Path) -> JSAnalysis:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return JSAnalysis(
        files_scanned=int(payload.get("files_scanned", 0)),
        findings=tuple(_finding_from_json(item) for item in payload.get("findings", [])),
        nodes=tuple(payload.get("nodes", [])),
        edges=tuple(payload.get("edges", [])),
    )


def _finding_from_json(item: dict[str, Any]) -> JSEvidence:
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
    return compare_analyses(semantic_scan_javascript(baseline_path), semantic_scan_javascript(candidate_path))
