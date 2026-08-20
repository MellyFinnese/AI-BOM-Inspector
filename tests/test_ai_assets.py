from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from aibom_inspector.ai_assets import (
    AIBOMDocument, AIBOMIndex, AIAsset, AIRelationship, ArtifactIdentity,
    DatasetLineage, DeploymentContext, EvaluationEvidence, ModelVersion,
    TrainingProvenance, artifact_id_from_digest, artifact_identity_from_bytes,
    stable_asset_id,
)


def make_document() -> AIBOMDocument:
    model = AIAsset(id="model:fraud-detector", kind="model", name="fraud-detector", provider="acme")
    base = AIAsset(id="model:base", kind="model", name="base-model")
    dataset = AIAsset(id="dataset:transactions", kind="dataset", name="transactions")
    runtime = AIAsset(id="runtime:prod", kind="runtime", name="prod-runtime")
    api = AIAsset(id="api:predict", kind="api", name="predict-api")
    agent = AIAsset(id="agent:risk", kind="agent", name="risk-agent")
    prompt = AIAsset(id="prompt:risk", kind="prompt", name="risk-prompt")
    tool = AIAsset(id="tool:ledger", kind="tool", name="ledger-tool")
    app = AIAsset(id="app:fraud", kind="deployment", name="fraud-prod")
    artifact = ArtifactIdentity(id=artifact_id_from_digest("a" * 64), digest="a" * 64)
    version = ModelVersion(id="model-version:fraud:v2", model_id=model.id, version="2", artifact_ids=[artifact.id])
    provenance = TrainingProvenance(
        id="training:fraud:v2", model_version_id=version.id, run_type="fine_tuning",
        dataset_lineage=[DatasetLineage(dataset_id=dataset.id, role="fine_tuning")],
        code_commit="abcdef1234567", framework="pytorch",
    )
    deployment = DeploymentContext(
        id="deployment-context:prod", application_id=app.id, model_version_id=version.id,
        environment="prod", criticality="high", data_sensitivity="confidential",
        endpoint_ids=[api.id], runtime_ids=[runtime.id],
    )
    evaluation = EvaluationEvidence(
        id="evaluation:fraud:baseline", model_version_id=version.id,
        suite="fraud-regression", passed=True, metrics={"f1": 0.91},
        dataset_id=dataset.id, evaluated_at=datetime.now(timezone.utc),
    )
    relationships = [
        AIRelationship(from_id=version.id, to_id=model.id, type="VERSION_OF"),
        AIRelationship(from_id=version.id, to_id=base.id, type="FINE_TUNED_FROM"),
        AIRelationship(from_id=provenance.id, to_id=dataset.id, type="TRAINED_ON"),
        AIRelationship(from_id=provenance.id, to_id=version.id, type="PRODUCES"),
        AIRelationship(from_id=version.id, to_id=artifact.id, type="PACKAGED_AS"),
        AIRelationship(from_id=deployment.id, to_id=version.id, type="DEPLOYED_AS"),
        AIRelationship(from_id=deployment.id, to_id=runtime.id, type="RUNS_ON"),
        AIRelationship(from_id=deployment.id, to_id=api.id, type="EXPOSES"),
        AIRelationship(from_id=agent.id, to_id=api.id, type="CALLS"),
        AIRelationship(from_id=agent.id, to_id=tool.id, type="INVOKES"),
        AIRelationship(from_id=agent.id, to_id=prompt.id, type="CONFIGURES"),
        AIRelationship(from_id=evaluation.id, to_id=version.id, type="EVALUATED_BY"),
    ]
    return AIBOMDocument(
        assets=[model, base, dataset, runtime, api, agent, prompt, tool, app],
        model_versions=[version], artifact_identities=[artifact],
        training_provenance=[provenance], deployments=[deployment],
        evaluations=[evaluation], relationships=relationships,
    )


def test_lineage_and_downstream_queries_are_reference_safe() -> None:
    index = AIBOMIndex(make_document())
    assert "dataset:transactions" in index.lineage("model-version:fraud:v2")
    assert "runtime:prod" in index.downstream("deployment-context:prod")
    assert "model-version:fraud:v2" in index.downstream("deployment-context:prod")
    assert "api:predict" in index.downstream("agent:risk")


def test_duplicate_ids_are_rejected() -> None:
    with pytest.raises(ValidationError, match="duplicate AI-BOM id"):
        AIBOMDocument(assets=[
            AIAsset(id="dup", kind="model", name="one"),
            AIAsset(id="dup", kind="dataset", name="two"),
        ])


def test_unknown_relationship_target_is_rejected() -> None:
    with pytest.raises(ValidationError, match="relationship target does not exist"):
        AIBOMDocument(
            assets=[AIAsset(id="model:a", kind="model", name="a")],
            relationships=[AIRelationship(from_id="model:a", to_id="missing", type="DERIVED_FROM")],
        )


def test_artifact_identity_is_deterministic() -> None:
    first = artifact_identity_from_bytes(b"weights", name="model.safetensors")
    second = artifact_identity_from_bytes(b"weights", name="model.safetensors")
    assert first.id == second.id
    assert first.digest == second.digest
    assert first.size == 7


def test_stable_asset_id_is_case_and_whitespace_insensitive() -> None:
    assert stable_asset_id("model", "Fraud-Detector", "2", "ACME") == stable_asset_id(
        "MODEL", "fraud-detector", "2", "acme"
    )


def test_artifact_requires_digest_or_uri() -> None:
    with pytest.raises(ValidationError, match="requires a digest or immutable URI"):
        ArtifactIdentity(id="artifact:missing")
