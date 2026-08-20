from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Iterable

from .ai_assets import AIBOMDocument, AIAsset, AIBOMIndex, AIRelationship


@dataclass(frozen=True)
class AssetIdentity:
    """Canonical identity material used to compare AI assets across scans."""

    kind: str
    name: str
    provider: str | None = None
    version: str | None = None
    digest: str | None = None

    @property
    def key(self) -> str:
        if self.digest:
            return f"{self.kind}:digest:{self.digest.lower()}"
        parts = [self.kind.lower(), normalize_name(self.name)]
        if self.provider:
            parts.append(normalize_name(self.provider))
        if self.version:
            parts.append(normalize_name(self.version))
        return ":".join(parts)


def normalize_name(value: str) -> str:
    return " ".join(value.strip().lower().replace("/", " ").replace("_", "-").split())


def index_canonical_identities(document: AIBOMDocument) -> dict[str, str]:
    """Map every AI-BOM object id to a stable identity key."""
    identities: dict[str, str] = {}
    for asset in document.assets:
        identities[asset.id] = asset_identity(asset, document).key

    model_assets = {asset.id: asset for asset in document.assets if asset.kind == "model"}
    for artifact in document.artifact_identities:
        identities[artifact.id] = AssetIdentity(
            kind="artifact",
            name=artifact.media_type or "artifact",
            digest=artifact.digest,
        ).key

    for version in document.model_versions:
        model = model_assets.get(version.model_id)
        identities[version.id] = AssetIdentity(
            kind="model_version",
            name=model.name if model else version.model_id,
            provider=version.provider or (model.provider if model else None),
            version=version.version,
        ).key
    return identities


def asset_identity(asset: AIAsset, document: AIBOMDocument) -> AssetIdentity:
    digest = None
    if asset.artifact_ids:
        artifacts = {item.id: item for item in document.artifact_identities}
        for artifact_id in asset.artifact_ids:
            artifact = artifacts.get(artifact_id)
            if artifact and artifact.digest:
                digest = artifact.digest
                break
    return AssetIdentity(
        kind=asset.kind,
        name=asset.name,
        provider=asset.provider,
        version=asset.version,
        digest=digest,
    )


@dataclass(frozen=True)
class EvidenceChain:
    """A compact, auditable relationship from a claim to supporting evidence."""

    claim: str
    asset_id: str
    evidence_ids: tuple[str, ...] = ()
    relationship_type: str | None = None
    confidence: str = "unknown"


@dataclass
class AIBOMDiff:
    added_assets: list[str] = field(default_factory=list)
    removed_assets: list[str] = field(default_factory=list)
    changed_assets: list[dict[str, str]] = field(default_factory=list)
    added_relationships: list[dict[str, str]] = field(default_factory=list)
    removed_relationships: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "added_assets": self.added_assets,
            "removed_assets": self.removed_assets,
            "changed_assets": self.changed_assets,
            "added_relationships": self.added_relationships,
            "removed_relationships": self.removed_relationships,
        }


def diff_ai_bom(previous: AIBOMDocument, current: AIBOMDocument) -> AIBOMDiff:
    """Compare two AI-BOM snapshots using canonical identities, not raw IDs."""
    prev_keys = index_canonical_identities(previous)
    curr_keys = index_canonical_identities(current)
    prev_by_key = {key: object_id for object_id, key in prev_keys.items()}
    curr_by_key = {key: object_id for object_id, key in curr_keys.items()}

    diff = AIBOMDiff()
    diff.added_assets = sorted(key for key in curr_by_key if key not in prev_by_key)
    diff.removed_assets = sorted(key for key in prev_by_key if key not in curr_by_key)

    common = sorted(set(prev_by_key) & set(curr_by_key))
    prev_objs = {obj.id: obj for obj in _objects(previous)}
    curr_objs = {obj.id: obj for obj in _objects(current)}
    for key in common:
        old_id = prev_by_key[key]
        new_id = curr_by_key[key]
        old = prev_objs.get(old_id)
        new = curr_objs.get(new_id)
        if old is None or new is None:
            continue
        if _object_signature(old) != _object_signature(new):
            diff.changed_assets.append({"identity": key, "previous": old_id, "current": new_id})

    prev_edges = {_edge_signature(edge, prev_keys) for edge in previous.relationships}
    curr_edges = {_edge_signature(edge, curr_keys) for edge in current.relationships}
    for edge in sorted(curr_edges - prev_edges):
        diff.added_relationships.append(_edge_dict(edge))
    for edge in sorted(prev_edges - curr_edges):
        diff.removed_relationships.append(_edge_dict(edge))
    return diff


def blast_radius(document: AIBOMDocument, start_id: str, *, max_depth: int = 32) -> set[str]:
    return AIBOMIndex(document).downstream(start_id, max_depth=max_depth)


def lineage(document: AIBOMDocument, model_version_id: str, *, max_depth: int = 32) -> set[str]:
    return AIBOMIndex(document).upstream(model_version_id, max_depth=max_depth)


def attack_paths(
    document: AIBOMDocument,
    start_id: str,
    targets: Iterable[str],
    *,
    max_depth: int = 12,
    relationship_types: set[str] | None = None,
) -> list[list[str]]:
    """Enumerate deterministic relationship paths to requested targets."""
    targets_set = set(targets)
    adjacency: dict[str, list[AIRelationship]] = {}
    for edge in document.relationships:
        if relationship_types and edge.type not in relationship_types:
            continue
        adjacency.setdefault(edge.from_id, []).append(edge)

    paths: list[list[str]] = []
    queue = deque([(start_id, [start_id])])
    while queue:
        current, path = queue.popleft()
        if current in targets_set and current != start_id:
            paths.append(path)
            continue
        if len(path) - 1 >= max_depth:
            continue
        for edge in adjacency.get(current, []):
            if edge.to_id in path:
                continue
            queue.append((edge.to_id, path + [edge.to_id]))
    return paths


def risk_reachability(document: AIBOMDocument, finding_asset_id: str) -> dict[str, object]:
    """Return deterministic impact facts without changing the risk score."""
    affected = blast_radius(document, finding_asset_id)
    models = {asset.id for asset in document.assets if asset.kind in {"model", "model_version"}}
    deployments = {asset.id for asset in document.assets if asset.kind == "deployment"}
    agents = {asset.id for asset in document.assets if asset.kind == "agent"}
    return {
        "finding_asset_id": finding_asset_id,
        "affected_assets": sorted(affected),
        "affected_models": sorted(affected & models),
        "affected_deployments": sorted(affected & deployments),
        "affected_agents": sorted(affected & agents),
    }


def evidence_chain_for_relationship(document: AIBOMDocument, relationship: AIRelationship) -> EvidenceChain:
    confidence = "confirmed" if relationship.evidence else "declared"
    evidence_ids = tuple(ref.source + "#" + ref.locator for ref in relationship.evidence)
    return EvidenceChain(
        claim=f"{relationship.from_id} {relationship.type} {relationship.to_id}",
        asset_id=relationship.to_id,
        evidence_ids=evidence_ids,
        relationship_type=relationship.type,
        confidence=confidence,
    )


def _objects(document: AIBOMDocument) -> list[object]:
    return [
        *document.assets,
        *document.model_versions,
        *document.artifact_identities,
        *document.training_provenance,
        *document.deployments,
        *document.evaluations,
    ]


def _object_signature(obj: object) -> str:
    data = obj.model_dump(exclude={"id"})
    return sha256(repr(sorted(data.items())).encode("utf-8")).hexdigest()


def _edge_signature(edge: AIRelationship, identities: dict[str, str]) -> tuple[str, str, str]:
    return (identities.get(edge.from_id, edge.from_id), identities.get(edge.to_id, edge.to_id), edge.type)


def _edge_dict(edge: tuple[str, str, str]) -> dict[str, str]:
    return {"from": edge[0], "to": edge[1], "type": edge[2]}
