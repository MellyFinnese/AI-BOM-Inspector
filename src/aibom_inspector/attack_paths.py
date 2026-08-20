from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from hashlib import sha256

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


def _severity(relationships: tuple[str, ...], target_symbol: str) -> str:
    target = target_symbol.lower()
    if "CAN_REACH" in relationships and any(token in target for token in ("exec", "spawn", "unlink", "rm", "writefile")):
        return "critical"
    if "CAN_REACH" in relationships:
        return "high"
    if "FLOWS_TO" in relationships:
        return "medium"
    return "low"


def _stable_path_id(nodes: tuple[str, ...], relationships: tuple[str, ...]) -> str:
    return "impact:" + sha256("|".join((*nodes, *relationships)).encode("utf-8")).hexdigest()[:24]


def discover_impact_paths(analysis: JSAnalysis, *, max_depth: int = 8, max_paths: int = 100) -> list[AttackPath]:
    """Find bounded, cycle-safe evidence paths from untrusted inputs to side effects."""
    node_map = {node["id"]: node for node in analysis.nodes}
    adjacency: dict[str, list[tuple[str, str]]] = {}
    for edge in analysis.edges:
        adjacency.setdefault(edge["source"], []).append((edge["target"], edge["relationship"]))

    sources = sorted(node_id for node_id, node in node_map.items() if node.get("kind") == "input")
    queue: deque[tuple[str, tuple[str, ...], tuple[str, ...]]] = deque((src, (src,), ()) for src in sources)
    paths: list[AttackPath] = []
    visited: set[tuple[str, tuple[str, ...]]] = set()

    while queue and len(paths) < max_paths:
        current, nodes, relationships = queue.popleft()
        state = (current, relationships)
        if state in visited:
            continue
        visited.add(state)
        if len(nodes) - 1 >= max_depth:
            continue
        for target, relationship in sorted(adjacency.get(current, [])):
            if target in nodes:
                continue
            next_nodes = nodes + (target,)
            next_relationships = relationships + (relationship,)
            target_node = node_map.get(target, {})
            if target_node.get("kind") == "privileged-operation":
                paths.append(
                    AttackPath(
                        path_id=_stable_path_id(next_nodes, next_relationships),
                        source=nodes[0],
                        target=target,
                        nodes=next_nodes,
                        relationships=next_relationships,
                        severity=_severity(next_relationships, target_node.get("symbol", target)),
                        evidence=tuple(node_map[node_id].get("file", "") for node_id in next_nodes if node_map.get(node_id, {}).get("file")),
                    )
                )
                continue
            queue.append((target, next_nodes, next_relationships))
    return paths


def diff_impact_paths(baseline: JSAnalysis, candidate: JSAnalysis, *, max_depth: int = 8, max_paths: int = 100) -> dict[str, object]:
    old = {path.path_id: path for path in discover_impact_paths(baseline, max_depth=max_depth, max_paths=max_paths)}
    new = {path.path_id: path for path in discover_impact_paths(candidate, max_depth=max_depth, max_paths=max_paths)}
    added = [new[key] for key in sorted(new.keys() - old.keys())]
    removed = [old[key] for key in sorted(old.keys() - new.keys())]
    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    maximum = max((path.severity for path in added), key=lambda value: rank[value], default="low")
    return {
        "impact_paths_added": [path.to_dict() for path in added],
        "impact_paths_removed": [path.to_dict() for path in removed],
        "impact_path_added": bool(added),
        "impact_path_count_added": len(added),
        "impact_path_count_removed": len(removed),
        "max_added_severity": maximum,
    }
