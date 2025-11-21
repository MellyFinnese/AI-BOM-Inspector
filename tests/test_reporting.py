import json
from datetime import datetime
from datetime import datetime
import json

from aibom_inspector.reporting import render_json, render_markdown
from aibom_inspector.types import DependencyInfo, DependencyIssue, ModelInfo, ModelIssue, Report


def test_render_json_contains_risk_score_and_flags():
    report = Report(
        dependencies=[
            DependencyInfo(
                name="pkg",
                version=None,
                source="requirements.txt",
                issues=[DependencyIssue("[MISSING_PIN] Dependency is not pinned", severity="high")],
            )
        ],
        models=[
            ModelInfo(
                identifier="model-x",
                source="huggingface",
                issues=[ModelIssue("[UNKNOWN_LICENSE] Missing license information", severity="high")],
            )
        ],
        generated_at=datetime.utcnow(),
    )

    payload = json.loads(render_json(report))
    assert payload["stack_risk_score"] < 100
    flat_issues = "".join(json.dumps(payload["dependencies"]) + json.dumps(payload["models"]))
    assert "MISSING_PIN" in flat_issues
    assert "UNKNOWN_LICENSE" in flat_issues


def test_markdown_renders_risk_score_header():
    report = Report(dependencies=[], models=[], generated_at=datetime.utcnow())
    markdown = render_markdown(report)
    assert "Stack Risk Score" in markdown
