from __future__ import annotations

from datetime import datetime

from aibom_inspector.ai_bom_builder import build_ai_bom
from aibom_inspector.types_models import ModelInfo
from aibom_inspector.types_report import Application, Report, RuntimeTrace


def test_builder_maps_model_lineage_dataset_artifact_and_deployment():
    model = ModelInfo(
        identifier="fraud-v2",
        source="acme",
        base_models=["base-v1"],
        fine_tuned_from=["base-v1"],
        training_sources=["dataset://transactions/v3"],
        hashes=["a" * 64],
        deployed_to="fraud-prod",
    )
    report = Report(
        dependencies=[],
        models=[model],
        applications=[Application(name="fraud-prod", environment="prod", criticality="high")],
        generated_at=datetime.utcnow(),
        runtime_trace=RuntimeTrace(
            trace_mode="trace",
            captured_at=datetime.utcnow(),
            command=["python", "app.py"],
        ),
    )

    bom = build_ai_bom(report)
    kinds = {asset.kind for asset in bom.assets}
    assert {"model", "dataset", "deployment", "runtime"}.issubset(kinds)
    assert any(rel.type == "FINE_TUNED_FROM" for rel in bom.relationships)
    assert any(rel.type == "TRAINED_ON" for rel in bom.relationships)
    assert any(rel.type == "DEPLOYED_AS" for rel in bom.relationships)
    assert any(rel.type == "PACKAGED_AS" for rel in bom.relationships)


def test_evaluation_evidence_is_represented_without_changing_risk():
    report = Report(
        dependencies=[],
        models=[ModelInfo(identifier="model-a", source="acme")],
        generated_at=datetime.utcnow(),
        evaluation_evidence=[
            {
                "id": "eval:model-a",
                "model": "model-a",
                "version": "1",
                "suite": "smoke",
                "passed": True,
                "metrics": {"accuracy": 0.99},
            }
        ],
    )
    before = report.stack_risk_score
    bom = build_ai_bom(report)
    assert report.stack_risk_score == before
    assert len(bom.evaluations) == 1
    assert bom.evaluations[0].passed is True
