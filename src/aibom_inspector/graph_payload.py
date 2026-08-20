from __future__ import annotations

from typing import Any

from .js_analysis import JSAnalysis


def build_graph_payload(analysis: JSAnalysis) -> dict[str, Any]:
    """Return a backend-neutral graph payload suitable for Memgraph ingestion."""
    return {
        "schema_version": "aibom-js-graph.v1",
        "nodes": [
            {"id": node["id"], "kind": node.get("kind", "unknown"), "symbol": node.get("symbol", ""), "file": node.get("file", "")}
            for node in analysis.nodes
        ],
        "edges": [
            {"source": edge["source"], "relationship": edge["relationship"], "target": edge["target"]}
            for edge in analysis.edges
        ],
    }
