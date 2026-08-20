from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from hashlib import sha256
from typing import Iterable

from .js_analysis import JSAnalysis


@dataclass(frozen=True)
class AttackPath:
    path_id: str
    source: str
    target: str
    nodes: tuple[str, ...]
    relationships: tuple[str, ...]
    severity: str
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "path_id": self.path_id,
            "source": self.source,
            "target": self.target,
            "nodes": list(self.nodes),
            "relationships": list(self.relationships),
            "severity": self.severity,
            "evidence": list(self.evidence),
        }


def _severity(relationships: Iterable[str], target: str) -> str:
    rels = set(relationships)
    target_lower = target.lower()
    if "CAN_REACH" in rels and any(token in target_lower for token in ("exec", "spawn", "unlink", "rm", "writefile")):
        return "critical"
    if "CAN_REACH" in rels:
        return "high"
    if "FLOWS_TO" in rels:
        return "medium"
    return "low"


def _path_id(nodes: tuple[str, ...], relationships: tuple[str, ...]) -> str:
    material = "|".join([*nodes, *relationships])
    return "impact:" + sha256(material.encode("utf-8")).hexdigest()[:24]


def discover_impact_paths(
    analysis: JSAnalysis,
    *,
    max_depth: int = 8,
    max_paths: int = 100,
    source_kinds: set[str] | None = None,
    target_kinds: set[str] | None = None,
) -> list[AttackPath]:
    """Enumerate bounded evidence-backed paths from untrusted inputs to side effects."""
    source_kinds = source_kinds or {"input"}
    target_kinds = target_kinds or {"privileged-operation"}
    node_map = {node["id"]: node for node in analysis.nodes}
    adjacency: dict[str, list[tuple[str, str]]] = {}
    for edge in analysis.edges:
        adjacency.setdefault(edge["source"], []).append((edge["target"], edge["relationship"]))

    sources = sorted(node_id for node_id, node in node_map.items() if node.get("kind") in source_kinds)
    paths: list[AttackPath] = []
    queue: deque[tuple[str, tuple[str, ...], tuple[str, ...]]] = deque(
        (source, (source,), ()) for source in sources
    )
    seen_states: set[tuple[str, tuple[str, ...]]] = set()

    while queue and len(paths) < max_paths:
        current, nodes, relationships = queue.popleft()
        state = (current, relationships)
        if state in seen_states:
            continue
        seen_states.add(state)
        if len(nodes) - 1 >= max_depth:
            continue
        for target, relationship in sorted(adjacency.get(current, [])):
            if target in nodes:
                continue
            next_nodes = nodes + (target,)
            next_relationships = relationships + (relationship,)
            target_kind = node_map.get(target, {}).get("kind")
            if target_kind in target_kinds:
                paths.append(
                    AttackPath(
                        path_id=_path_id(next_nodes, next_relationships),
                        source=nodes[0],
                        target=target,
                        nodes=next_nodes,
                        relationships=next_relationships,
                        severity=_severity(next_relationships, node_map.get(target, {}).get("symbol", target)),
                        evidence=tuple(
                            node_map[node_id].get("file", "")
                            for node_id in next_nodes
                            if node_map.get(node_id, {}).get("file")
                        ),
                    )
                )
                continue
            queue.append((target, next_nodes, next_relationships))
    return paths


def diff_impact_paths(
    baseline: JSAnalysis,
    candidate: JSAnalysis,
    *,
    max_depth: int = 8,
    max_paths: int = 100,
) -> dict[str, object]:
    old = {path.path_id: path for path in discover_impact_paths(baseline, max_depth=max_depth, max_paths=max_paths)}
    new = {path.path_id: path for path in discover_impact_paths(candidate, max_depth=max_depth, max_paths=max_paths)}
    added = [new[key] for key in sorted(new.keys() - old.keys())]
    removed = [old[key] for key in sorted(old.keys() - new.keys())]
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    highest = "low"
    for path in added:
        if severity_order[path.severity] > severity_order[highest]:
            highest = path.severity
    return {
        "impact_paths_added": [path.to_dict() for path in added],
        "impact_paths_removed": [path.to_dict() for path in removed],
        "impact_path_added": bool(added),
        "impact_path_count_added": len(added),
        "impact_path_count_removed": len(removed),
        "max_added_severity": highest,
    }
