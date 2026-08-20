from datetime import datetime

from aibom_inspector.evidence_context import classify_evidence_context
from aibom_inspector.types import ModelInfo, ModelIssue, Report


def test_evidence_context_classifies_non_production_sources() -> None:
    assert classify_evidence_context("benchmark/ground_truth_public/openai.json") == "benchmark"
    assert classify_evidence_context("tests/fixtures/vulnerable-ai/app.py") == "test"
    assert classify_evidence_context("docs/architecture.md") == "documentation"
    assert classify_evidence_context("examples/trust-boundary-drift/app.py") == "example"
    assert classify_evidence_context("src/aibom/risk/rules.py") == "implementation"


def test_evidence_context_marks_application_code_as_production() -> None:
    assert classify_evidence_context("src/app.py") == "production"
    assert classify_evidence_context("app/api/chat.ts") == "production"


def test_model_evidence_signal_exposes_context_and_relevance() -> None:
    model = ModelInfo(
        identifier="gpt-3",
        source="openai",
        trust_signals=[
            ModelIssue(
                "[EVIDENCE] discovered in benchmark/ground_truth_public/openai.json",
                severity="low",
                code="EVIDENCE",
            )
        ],
    )

    signal = model.trust_signals[0]
    assert signal.metadata["evidence_context"] == "benchmark"
    assert signal.metadata["production_relevance"] is False
    assert signal.metadata["evidence_path"] == "benchmark/ground_truth_public/openai.json"
    assert model.primary_evidence_context == "benchmark"
    assert model.production_relevant is False


def test_mixed_evidence_promotes_model_to_production_relevance() -> None:
    model = ModelInfo(
        identifier="gpt-4o",
        source="openai",
        trust_signals=[
            ModelIssue(
                "[EVIDENCE] discovered in benchmark/ground_truth_public/openai.json",
                severity="low",
                code="EVIDENCE",
            ),
            ModelIssue(
                "[EVIDENCE] discovered in app/chat.py",
                severity="low",
                code="EVIDENCE",
            ),
        ],
    )

    assert model.evidence_contexts == {"benchmark", "production"}
    assert model.primary_evidence_context == "production"
    assert model.production_relevant is True


def test_nonproduction_model_reference_does_not_add_production_risk() -> None:
    model = ModelInfo(
        identifier="gpt-3",
        source="openai",
        issues=[ModelIssue("[UNKNOWN_LICENSE] Missing license information", severity="high", code="UNKNOWN_LICENSE")],
        trust_signals=[
            ModelIssue(
                "[EVIDENCE] discovered in benchmark/ground_truth_public/openai.json",
                severity="low",
                code="EVIDENCE",
            )
        ],
    )
    report = Report(dependencies=[], models=[model], generated_at=datetime.utcnow())

    assert model.risk_score == 3
    assert report.total_risk == 0
    assert report.risk_breakdown["nonproduction_model_references"] == 1
    assert report.risk_breakdown["unknown_licenses"] == 0
