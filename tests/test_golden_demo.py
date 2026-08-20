import json
from pathlib import Path


def test_demo_report_contains_policy_block():
    report_path = Path("demo/golden-vulnerable-ai/report.json")
    assert report_path.exists(), "Demo report.json should exist"
    data = json.loads(report_path.read_text())
    assert data.get("total_risk", 0) >= 70, "Demo should exceed the configured blocking threshold"
    ids = {f.get("id") for f in data.get("findings", [])}
    assert "PICKLE_DANGEROUS_GLOBALS" in ids, "Expected pickle finding present"
