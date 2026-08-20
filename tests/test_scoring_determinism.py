from __future__ import annotations

from datetime import datetime, timezone

from aibom_inspector.scoring_models import DefaultScoreModel, OrgContext, ScoringContext
from aibom_inspector.types import DependencyInfo, DependencyIssue, ModelInfo, ModelIssue, Report, RiskSettings


def _report() -> Report:
    return Report(
        dependencies=[
            DependencyInfo(
                name="example-pkg",
                version="1.2.3",
                source="requirements.txt",
                issues=[
                    DependencyIssue(
                        message="known vulnerability",
                        severity="high",
                        code="CVE-2026-0001",
                        metadata={"exploit_maturity": "poc"},
                    ),
                    DependencyIssue(
                        message="known vulnerability duplicate",
                        severity="high",
                        code="CVE-2026-0001",
                        metadata={"exploit_maturity": "mature"},
                    ),
                ],
            )
        ],
        models=[
            ModelInfo(
                identifier="model-a",
                source="registry/model-a",
                license="Apache-2.0",
                hashes=["bbb", "aaa"],
                issues=[
                    ModelIssue(message="model issue", severity="medium", code="MODEL_RISK"),
                ],
            ),
            ModelInfo(
                identifier="model-b",
                source="registry/model-b",
                license="Apache-2.0",
                hashes=["ccc"],
                trust_signals=[
                    ModelIssue(
                        message="[EVIDENCE] discovered in examples/model.py",
                        severity="low",
                        code="EVIDENCE",
                    )
                ],
            ),
        ],
        generated_at=datetime(2026, 8, 20, 15, 0, tzinfo=timezone.utc),
        risk_settings=RiskSettings(),
    )


def _context() -> ScoringContext:
    return ScoringContext(
        org_context=OrgContext(
            asset_criticality="high",
            data_sensitivity="confidential",
            environment="prod",
        ),
        policy_metadata={"version": "1"},
        intel_versions={"osv": "2026-08"},
    )


def test_score_explanation_is_deterministic_for_same_report() -> None:
    report = _report()
    model = DefaultScoreModel()

    first = model.score(report, _context())
    second = model.score(report, _context())

    assert first.final_score == second.final_score
    assert first.total_penalty == second.total_penalty
    assert first.explanation == second.explanation


def test_model_snapshot_is_order_independent() -> None:
    first_report = _report()
    second_report = _report()
    second_report.models.reverse()

    model = DefaultScoreModel()
    first = model.score(first_report, _context())
    second = model.score(second_report, _context())

    assert first.explanation["model_snapshot"] == second.explanation["model_snapshot"]


def test_duplicate_findings_get_distinct_graph_nodes() -> None:
    outcome = DefaultScoreModel().score(_report(), _context())
    nodes = outcome.explanation["graph"]["nodes"]
    ids = [node["id"] for node in nodes]

    assert len(ids) == len(set(ids))
    assert sum(node["label"] == "example-pkg" for node in nodes) == 2
