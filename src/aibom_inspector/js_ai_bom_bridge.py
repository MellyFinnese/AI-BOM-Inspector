from __future__ import annotations

from hashlib import sha256

from .ai_assets import AIBOMDocument, AIAsset
from .attack_paths import discover_impact_paths
from .js_analysis import JSAnalysis


_KIND_MAP = {
    "provider": "api",
    "model_call": "model",
    "agent": "agent",
    "prompt-sink": "prompt",
    "tool": "tool",
    "privileged-operation": "tool",
}


def _asset_id(node_id: str) -> str:
    return "code:" + sha256(node_id.encode("utf-8")).hexdigest()[:24]


def bridge_js_analysis_to_aibom(document: AIBOMDocument, analysis: JSAnalysis) -> AIBOMDocument:
    """Attach AI-relevant code nodes and impact-path evidence to an existing AI-BOM."""
    assets = list(document.assets)
    existing = {asset.id for asset in assets}
    node_to_asset: dict[str, str] = {}

    for node in analysis.nodes:
        kind = _KIND_MAP.get(node.get("kind"))
        if not kind:
            continue
        node_id = node["id"]
        asset_id = _asset_id(node_id)
        node_to_asset[node_id] = asset_id
        if asset_id in existing:
            continue
        assets.append(
            AIAsset(
                id=asset_id,
                kind=kind,
                name=node.get("symbol", node_id),
                source=node.get("file"),
                metadata={"code_node_id": node_id, "code_kind": node.get("kind", "")},
            )
        )
        existing.add(asset_id)

    impact_paths = discover_impact_paths(analysis)
    metadata = dict(document.metadata)
    metadata["code_graph"] = {
        "schema_version": "ai-bom-code-graph.v1",
        "node_count": len(analysis.nodes),
        "edge_count": len(analysis.edges),
        "bridged_asset_ids": sorted(node_to_asset.values()),
    }
    metadata["code_impact_paths"] = [
        {
            **path.to_dict(),
            "source_asset_id": node_to_asset.get(path.source),
            "target_asset_id": node_to_asset.get(path.target),
        }
        for path in impact_paths
    ]
    return document.model_copy(update={"assets": assets, "metadata": metadata})
