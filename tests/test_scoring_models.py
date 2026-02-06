from __future__ import annotations

from datetime import datetime

from aibom_inspector.scoring_models import OrgContext, ScoringContext, get_score_model
from aibom_inspector.types import DependencyInfo, DependencyIssue, Report, RiskSettings


def test_active_exploitation_overrides_penalty() -> None:
    settings = RiskSettings(active_exploitation_penalty=30)
    dependency = DependencyInfo(
        name="example-lib",
        version="1.2.3",
        source="pypi",
        issues=[
            DependencyIssue(
                message="Known exploit",
                severity="low",
                code="CVE-2024-0001",
                metadata={"active_exploitation": True},
            )
        ],
    )
    report = Report(
        dependencies=[dependency],
        models=[],
        generated_at=datetime.utcnow(),
        risk_settings=settings,
    )

    outcome = get_score_model("default").score(
        report,
        ScoringContext(
            org_context=OrgContext(
                asset_criticality="medium",
                data_sensitivity="internal",
                environment="dev",
            ),
            policy_metadata=None,
            intel_versions=None,
        ),
    )

    contribution = outcome.explanation["issue_contributions"][0]
    assert contribution["override_applied"] is True
    assert contribution["penalty"] >= settings.active_exploitation_penalty
    assert outcome.explanation["kind"] == "score_explainability"
