from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .js_semantics import semantic_scan_javascript
from .js_analysis import JSAnalysis, JSEvidence, scan_javascript


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


def _node_kind(node_id: str, nodes: dict[str, dict[str, str]]) -> str:
    node = nodes.get(node_id)
    if node:
        return node.get("kind", "")
    parts = node_id.split(":")
    return parts[-2] if len(parts) >= 2 else ""


def _is_source(node_id: str, nodes: dict[str, dict[str, str]]) -> bool:
    kind = _node_kind(node_id, nodes)
    return kind in {"input", "variable"} and (":input:" in node_id or ":variable:" in node_id)


def _is_risk_sink(node_id: str, nodes: dict[str, dict[str, str]]) -> bool:
    kind = _node_kind(node_id, nodes)
    return kind in {"privileged-operation", "tool"}


def _risk_for_path(path_nodes: tuple[str, ...], nodes: dict[str, dict[str, str]]) -> str:
    kinds = {_node_kind(node_id, nodes) for node_id in path_nodes}
    if "privileged-operation" in kinds and "input" in kinds:
        return "critical"
    if "privileged-operation" in kinds or "tool" in kinds:
        return "high"
    return "medium"


def _impact_paths(analysis: JSAnalysis, *, max_depth: int = 8, max_paths: int = 200) -> tuple[dict[str, Any], ...]:
    nodes = {node["id"]: node for node in analysis.nodes if "id" in node}
    adjacency: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for edge in analysis.edges:
        source, relationship, target = _edge_key(edge)
        adjacency[source].append((relationship, target))

    sources = sorted(node_id for node_id in nodes if _is_source(node_id, nodes))
    paths: list[dict[str, Any]] = []
    seen_signatures: set[tuple[str, ...]] = set()

    for source in sources:
        queue: deque[tuple[str, tuple[str, ...], tuple[str, ...]]] = deque([(source, (source,), ())])
        while queue and len(paths) < max_paths:
            current, node_path, relationships = queue.popleft()
            if len(node_path) > max_depth:
                continue
            if current != source and _is_risk_sink(current, nodes):
                signature = node_path + relationships
                if signature not in seen_signatures:
                    seen_signatures.add(signature)
                    paths.append(
                        {
                            "nodes": list(node_path),
                            "relationships": list(relationships),
                            "severity": _risk_for_path(node_path, nodes),
                            "length": len(relationships),
                        }
                    )
                continue
            for relationship, target in sorted(adjacency.get(current, []), key=lambda item: (item[0], item[1])):
                if target in node_path:
                    continue
                queue.append((target, node_path + (target,), relationships + (relationship,)))

    return tuple(paths)


def _path_signature(path: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(path["nodes"]) + tuple(path["relationships"])


def compare_analyses(baseline: JSAnalysis, candidate: JSAnalysis) -> dict[str, Any]:
    old_edges = {_edge_key(e) for e in baseline.edges}
    new_edges = {_edge_key(e) for e in candidate.edges}
    old_findings = {(f.file, f.line, f.detector_id, f.symbol) for f in baseline.findings}
    new_findings = {(f.file, f.line, f.detector_id, f.symbol) for f in candidate.findings}

    old_nodes = {node["id"]: node for node in baseline.nodes if "id" in node}
    new_nodes = {node["id"]: node for node in candidate.nodes if "id" in node}
    old_paths = _impact_paths(baseline)
    new_paths = _impact_paths(candidate)
    old_path_keys = {_path_signature(path) for path in old_paths}
    new_path_keys = {_path_signature(path) for path in new_paths}

    changes: list[DriftChange] = []
    for source, relationship, target in sorted(new_edges - old_edges):
        severity = "critical" if relationship == "CAN_REACH" and ":input:" in source else "high"
        reason = "A new evidence-backed relationship was introduced."
        changes.append(DriftChange("edge_added", severity, source, relationship, target, reason))
    for source, relationship, target in sorted(old_edges - new_edges):
        changes.append(DriftChange("edge_removed", "info", source, relationship, target, "A previously observed relationship is no longer present."))

    for file, line, detector_id, symbol in sorted(new_findings - old_findings):
        severity = "medium"
        if detector_id.startswith("JS-TAINT") or detector_id.startswith("JS-TOOL"):
            severity = "high"
        changes.append(DriftChange("finding_added", severity, f"{file}:{line}", detector_id, symbol, "A new AI/security behavior was discovered."))

    added_paths = [path for path in new_paths if _path_signature(path) not in old_path_keys]
    for path in added_paths:
        nodes_in_path = path["nodes"]
        relationships = path["relationships"]
        changes.append(
            DriftChange(
                "impact_path_added",
                path["severity"],
                nodes_in_path[0] if nodes_in_path else None,
                relationships[0] if relationships else None,
                nodes_in_path[-1] if nodes_in_path else None,
                "A previously absent input-to-side-effect path is now reachable in the evidence graph.",
                tuple(nodes_in_path),
            )
        )

    removed_paths = [path for path in old_paths if _path_signature(path) not in new_path_keys]

    highest_path_severity = {"medium": 1, "high": 2, "critical": 3}
    impact_severity = "none"
    if added_paths:
        impact_severity = max((path["severity"] for path in added_paths), key=lambda item: highest_path_severity[item])

    return {
        "schema_version": "behavioral-drift.v2",
        "baseline_files": baseline.files_scanned,
        "candidate_files": candidate.files_scanned,
        "nodes_added": len(set(new_nodes) - set(old_nodes)),
        "nodes_removed": len(set(old_nodes) - set(new_nodes)),
        "edges_added": len(new_edges - old_edges),
        "edges_removed": len(old_edges - new_edges),
        "findings_added": len(new_findings - old_findings),
        "impact_paths_baseline": len(old_paths),
        "impact_paths_candidate": len(new_paths),
        "impact_paths_added": len(added_paths),
        "impact_paths_removed": len(removed_paths),
        "impact_path_added": bool(added_paths),
        "impact_severity": impact_severity,
        "impact_paths": added_paths,
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
    baseline = semantic_scan_javascript(baseline_path)
    candidate = semantic_scan_javascript(candidate_path)
    return compare_analyses(baseline, candidate)
