from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

AI_BOM_SCHEMA_VERSION = "0.2"

AssetKind = Literal[
    "model", "model_version", "dataset", "artifact", "training_run",
    "fine_tuning_run", "runtime", "api", "agent", "prompt", "tool",
    "deployment", "evaluation"
]

RelationshipType = Literal[
    "VERSION_OF", "DERIVED_FROM", "TRAINED_ON", "FINE_TUNED_FROM", "PRODUCES",
    "PACKAGED_AS", "DEPLOYED_AS", "RUNS_ON", "EXPOSES", "CALLS", "USES",
    "INVOKES", "CONFIGURES", "EVALUATED_BY", "ATTESTED_BY", "OWNED_BY"
]


class EvidenceRef(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    source: str
    kind: Literal["file", "url", "command", "attestation", "runtime", "manual"]
    locator: str
    sha256: str | None = Field(default=None, min_length=64, max_length=64, pattern=r"^[0-9a-fA-F]{64}$")


class ArtifactIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str
    digest_algorithm: Literal["sha256", "sha384", "sha512", "blake3"] = "sha256"
    digest: str | None = None
    media_type: str | None = None
    size: int | None = Field(default=None, ge=0)
    uri: str | None = None

    @model_validator(mode="after")
    def validate_identity(self) -> "ArtifactIdentity":
        if not self.digest and not self.uri:
            raise ValueError("artifact identity requires a digest or immutable URI")
        if self.digest_algorithm == "sha256" and self.digest:
            if len(self.digest) != 64 or any(c not in "0123456789abcdefABCDEF" for c in self.digest):
                raise ValueError("sha256 artifact digests must be 64 hexadecimal characters")
        return self


class AIAsset(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str
    kind: AssetKind
    name: str
    version: str | None = None
    provider: str | None = None
    source: str | None = None
    license: str | None = None
    artifact_ids: list[str] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ModelVersion(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str
    model_id: str
    version: str
    provider: str | None = None
    release_uri: str | None = None
    artifact_ids: list[str] = Field(default_factory=list)
    created_at: datetime | None = None
    evidence: list[EvidenceRef] = Field(default_factory=list)


class DatasetLineage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    dataset_id: str
    role: Literal["training", "validation", "test", "evaluation", "fine_tuning", "retrieval"] = "training"
    snapshot: str | None = None
    version: str | None = None
    transformations: list[str] = Field(default_factory=list)
    source_uri: str | None = None
    evidence: list[EvidenceRef] = Field(default_factory=list)


class TrainingProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str
    model_version_id: str
    run_type: Literal["training", "fine_tuning"] = "training"
    base_model_version_ids: list[str] = Field(default_factory=list)
    dataset_lineage: list[DatasetLineage] = Field(default_factory=list)
    code_uri: str | None = None
    code_commit: str | None = Field(default=None, min_length=7)
    framework: str | None = None
    framework_version: str | None = None
    compute: dict[str, Any] = Field(default_factory=dict)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    evidence: list[EvidenceRef] = Field(default_factory=list)


class DeploymentContext(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str
    application_id: str
    model_version_id: str
    environment: Literal["dev", "test", "staging", "prod", "unknown"] = "unknown"
    region: str | None = None
    criticality: Literal["low", "medium", "high", "critical", "unknown"] = "unknown"
    data_sensitivity: Literal["public", "internal", "confidential", "restricted", "unknown"] = "unknown"
    owner: str | None = None
    endpoint_ids: list[str] = Field(default_factory=list)
    runtime_ids: list[str] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)


class EvaluationEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str
    model_version_id: str
    suite: str
    passed: bool
    metrics: dict[str, float] = Field(default_factory=dict)
    dataset_id: str | None = None
    evaluator: str | None = None
    evaluated_at: datetime | None = None
    evidence: list[EvidenceRef] = Field(default_factory=list)


class AIRelationship(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    from_id: str
    to_id: str
    type: RelationshipType
    evidence: list[EvidenceRef] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def reject_self_edges(self) -> "AIRelationship":
        if self.from_id == self.to_id:
            raise ValueError("self-referential AI-BOM relationships are not allowed")
        return self


class AIBOMDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: str = AI_BOM_SCHEMA_VERSION
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    assets: list[AIAsset] = Field(default_factory=list)
    model_versions: list[ModelVersion] = Field(default_factory=list)
    artifact_identities: list[ArtifactIdentity] = Field(default_factory=list)
    training_provenance: list[TrainingProvenance] = Field(default_factory=list)
    deployments: list[DeploymentContext] = Field(default_factory=list)
    evaluations: list[EvaluationEvidence] = Field(default_factory=list)
    relationships: list[AIRelationship] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_references(self) -> "AIBOMDocument":
        ids: set[str] = set()
        objects = [*self.assets, *self.model_versions, *self.artifact_identities,
                   *self.training_provenance, *self.deployments, *self.evaluations]
        for obj in objects:
            if obj.id in ids:
                raise ValueError(f"duplicate AI-BOM id: {obj.id}")
            ids.add(obj.id)
        for rel in self.relationships:
            if rel.from_id not in ids:
                raise ValueError(f"relationship source does not exist: {rel.from_id}")
            if rel.to_id not in ids:
                raise ValueError(f"relationship target does not exist: {rel.to_id}")
        model_versions = {x.id for x in self.model_versions}
        artifacts = {x.id for x in self.artifact_identities}
        for version in self.model_versions:
            if version.model_id not in ids:
                raise ValueError(f"model version references unknown model: {version.model_id}")
            missing = set(version.artifact_ids) - artifacts
            if missing:
                raise ValueError(f"model version references unknown artifacts: {sorted(missing)}")
        for prov in self.training_provenance:
            if prov.model_version_id not in model_versions:
                raise ValueError(f"training provenance references unknown model version: {prov.model_version_id}")
            missing = set(prov.base_model_version_ids) - model_versions
            if missing:
                raise ValueError(f"training provenance references unknown base models: {sorted(missing)}")
            missing_ds = [x.dataset_id for x in prov.dataset_lineage if x.dataset_id not in ids]
            if missing_ds:
                raise ValueError(f"training provenance references unknown datasets: {sorted(set(missing_ds))}")
        for dep in self.deployments:
            if dep.model_version_id not in model_versions:
                raise ValueError(f"deployment references unknown model version: {dep.model_version_id}")
        for evaluation in self.evaluations:
            if evaluation.model_version_id not in model_versions:
                raise ValueError(f"evaluation references unknown model version: {evaluation.model_version_id}")
            if evaluation.dataset_id and evaluation.dataset_id not in ids:
                raise ValueError(f"evaluation references unknown dataset: {evaluation.dataset_id}")
        return self


class AIBOMIndex:
    """Read-only relationship index for lineage and blast-radius queries."""

    def __init__(self, document: AIBOMDocument) -> None:
        self.document = document
        self.edges = list(document.relationships)
        seen = {(edge.from_id, edge.to_id, edge.type) for edge in self.edges}

        def add_derived(from_id: str, to_id: str, relationship_type: RelationshipType) -> None:
            key = (from_id, to_id, relationship_type)
            if from_id in self._object_ids and to_id in self._object_ids and key not in seen:
                self.edges.append(AIRelationship(from_id=from_id, to_id=to_id, type=relationship_type))
                seen.add(key)

        self._object_ids = {
            obj.id for obj in [
                *document.assets,
                *document.model_versions,
                *document.artifact_identities,
                *document.training_provenance,
                *document.deployments,
                *document.evaluations,
            ]
        }

        for version in document.model_versions:
            add_derived(version.id, version.model_id, "VERSION_OF")
            for artifact_id in version.artifact_ids:
                add_derived(version.id, artifact_id, "PACKAGED_AS")

        for provenance in document.training_provenance:
            add_derived(provenance.id, provenance.model_version_id, "PRODUCES")
            for base_id in provenance.base_model_version_ids:
                add_derived(provenance.id, base_id, "FINE_TUNED_FROM")
            for lineage in provenance.dataset_lineage:
                add_derived(provenance.id, lineage.dataset_id, "TRAINED_ON")

        for deployment in document.deployments:
            add_derived(deployment.id, deployment.model_version_id, "DEPLOYED_AS")
            for runtime_id in deployment.runtime_ids:
                add_derived(deployment.id, runtime_id, "RUNS_ON")
            for endpoint_id in deployment.endpoint_ids:
                add_derived(deployment.id, endpoint_id, "EXPOSES")

        for evaluation in document.evaluations:
            add_derived(evaluation.id, evaluation.model_version_id, "EVALUATED_BY")
            if evaluation.dataset_id:
                add_derived(evaluation.id, evaluation.dataset_id, "TRAINED_ON")

        self._out: dict[str, list[AIRelationship]] = defaultdict(list)
        self._in: dict[str, list[AIRelationship]] = defaultdict(list)
        for edge in self.edges:
            self._out[edge.from_id].append(edge)
            self._in[edge.to_id].append(edge)

    def downstream(self, start_id: str, *, max_depth: int = 32) -> set[str]:
        return self._walk(start_id, outgoing=True, max_depth=max_depth)

    def upstream(self, start_id: str, *, max_depth: int = 32) -> set[str]:
        return self._walk(start_id, outgoing=False, max_depth=max_depth)

    def lineage(self, model_version_id: str) -> set[str]:
        return self.upstream(model_version_id)

    def _walk(self, start_id: str, *, outgoing: bool, max_depth: int) -> set[str]:
        adjacency = self._out if outgoing else self._in
        seen: set[str] = set()
        queue = deque([(start_id, 0)])
        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for edge in adjacency.get(current, []):
                nxt = edge.to_id if outgoing else edge.from_id
                if nxt == start_id or nxt in seen:
                    continue
                seen.add(nxt)
                queue.append((nxt, depth + 1))
        return seen


def stable_asset_id(kind: str, name: str, version: str | None = None, provider: str | None = None) -> str:
    canonical = "|".join((kind, name, version or "", provider or "")).strip().lower()
    return f"{kind.strip().lower()}:{sha256(canonical.encode()).hexdigest()[:24]}"


def artifact_id_from_digest(digest: str, algorithm: str = "sha256") -> str:
    return f"artifact:{algorithm}:{digest.strip().lower()}"


def artifact_identity_from_bytes(data: bytes, *, name: str, media_type: str | None = None,
                                 uri: str | None = None) -> ArtifactIdentity:
    digest = sha256(data).hexdigest()
    return ArtifactIdentity(id=artifact_id_from_digest(digest), digest=digest,
                            media_type=media_type, size=len(data), uri=uri)