import json
from pathlib import Path


def test_demo_report_contains_policy_block():
    report_path = Path("demo/golden-vulnerable-ai/report.json")
    assert report_path.exists(), "Demo report.json should exist"
    data = json.loads(report_path.read_text())
    assert data.get("total_risk", 0) >= 70, "Demo should exceed the configured blocking threshold"
    assert data.get("provenance", {}).get("git_commit"), "Demo report should retain provenance"
    assert data.get("policy_metadata", {}).get("policy_hash"), "Demo report should retain policy metadata"
