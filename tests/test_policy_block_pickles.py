from datetime import datetime
from aibom_inspector.policy import Policy, evaluate_policy
from aibom_inspector.types import ModelInfo, Report, IntegrityFinding


def test_block_legacy_pickles_model():
    model = ModelInfo(identifier="models/bad_model.pkl", source="local", license="MIT")
    report = Report(dependencies=[], models=[model], generated_at=datetime.utcnow())
    policy = Policy(block_legacy_pickles=True)

    evaluation = evaluate_policy(report, policy)
    assert not evaluation.passed
    assert any("legacy format" in f.lower() or "pkl" in f.lower() for f in evaluation.failures)


def test_block_legacy_pickles_integrity_finding():
    finding = IntegrityFinding(kind="file", path="artifacts/weights.pt", message="found legacy model file", severity="high")
    report = Report(dependencies=[], models=[], generated_at=datetime.utcnow(), integrity_findings=[finding])
    policy = Policy(block_legacy_pickles=True)

    evaluation = evaluate_policy(report, policy)
    assert not evaluation.passed
    assert any("legacy format" in f.lower() or "pt" in f.lower() for f in evaluation.failures)
