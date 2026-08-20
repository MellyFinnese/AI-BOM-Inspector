from __future__ import annotations

from aibom_inspector.ai_assets import AIAsset, AIBOMDocument, AIRelationship, ArtifactIdentity, ModelVersion
from aibom_inspector.ai_bom_reasoning import (
    attack_paths,
    blast_radius,
    diff_ai_bom,
    evidence_chain_for_relationship,
    index_canonical_identities,
    lineage,
)


def make_doc(*, changed: bool = False) -> AIBOMDocument:
    model_id = "model:fraud"
    version_id = "model-version:fraud-v2"
    digest = ("b" if changed else "a") * 64
    artifact_id = "artifact:sha256:" + digest
    deployment_id = "deployment:prod"
    agent_id = "agent:risk"
    api_id = "api:predict"
    return AIBOMDocument(
        assets=[
            AIAsset(id=model_id, kind="model", name="Fraud_Model", provider="ACME"),
            AIAsset(id=deployment_id, kind="deployment", name="fraud-prod"),
            AIAsset(id=agent_id, kind="agent", name="risk-agent"),
            AIAsset(id=api_id, kind="api", name="predict-api"),
        ],
        model_versions=[
            ModelVersion(id=version_id, model_id=model_id, version="2", artifact_ids=[artifact_id])
        ],
        artifact_identities=[ArtifactIdentity(id=artifact_id, digest=digest)],
        relationships=[
            AIRelationship(from_id=version_id, to_id=model_id, type="VERSION_OF"),
            AIRelationship(from_id=deployment_id, to_id=version_id, type="DEPLOYED_AS"),
            AIRelationship(from_id=deployment_id, to_id=api_id, type="EXPOSES"),
            AIRelationship(from_id=agent_id, to_id=api_id, type="CALLS"),
        ],
    )


def test_canonical_identity_normalizes_names_and_keeps_version_stable():
    identities = index_canonical_identities(make_doc())
    assert identities["model:fraud"].startswith("model:fraud-model:acme")
    assert identities["model-version:fraud-v2"].startswith("model_version:fraud-model:acme:2")
    assert identities["artifact:sha256:" + "a" * 64].endswith("a" * 64)


def test_blast_radius_and_lineage_are_deterministic():
    doc = make_doc()
    assert "model:fraud" in lineage(doc, "model-version:fraud-v2")
    affected = blast_radius(doc, "deployment:prod")
    assert "model-version:fraud-v2" in affected
    assert "api:predict" in affected


def test_attack_paths_reach_agent_through_deployment_api():
    doc = make_doc()
    paths = attack_paths(
        doc,
        "deployment:prod",
        {"agent:risk"},
        relationship_types={"DEPLOYED_AS", "EXPOSES", "CALLS"},
    )
    assert ["deployment:prod", "api:predict", "agent:risk"] in paths


def test_diff_detects_artifact_replacement_without_fake_model_addition():
    diff = diff_ai_bom(make_doc(changed=False), make_doc(changed=True))
    assert not any(item.startswith("model:fraud") for item in diff.added_assets + diff.removed_assets)
    assert any(item.startswith("artifact:digest:") for item in diff.added_assets)
    assert any(item.startswith("artifact:digest:") for item in diff.removed_assets)


def test_evidence_chain_marks_undeclared_edges_declared():
    doc = make_doc()
    edge = doc.relationships[1]
    chain = evidence_chain_for_relationship(doc, edge)
    assert chain.relationship_type == "DEPLOYED_AS"
    assert chain.confidence == "declared"
