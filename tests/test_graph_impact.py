import json
from pathlib import Path

from click.testing import CliRunner

from aibom_inspector.cli import main


def test_graph_impact_basic(tmp_path: Path):
    runner = CliRunner()
    report = {
        "generated_at": "2026-01-01T00:00:00",
        "dependencies": [
            {
                "name": "vuln_pkg",
                "version": "1.2.3",
                "source": "requirements.txt",
                "issue_details": [
                    {"message": "[CVE] CVE-TEST-1: example vulnerability", "severity": "high", "code": "CVE-TEST-1"}
                ],
            }
        ],
        "models": [
            {
                "id": "model-alpha",
                "supporting_dependencies": ["vuln_pkg"],
                "deployed_to": "app-1",
            },
            {
                "id": "model-beta",
                "supporting_dependencies": [
                    {"name": "vuln_pkg", "start_date": "2020-01-01", "end_date": "2030-01-01"}
                ],
                "deployed_to": "app-2",
            },
        ],
        "applications": [
            {"name": "app-1", "owner": "alice"},
            {"name": "app-2", "owner": "bob"},
        ],
    }

    p = tmp_path / "report.json"
    p.write_text(json.dumps(report))

    result = runner.invoke(main, ["graph", "impact", "--report", str(p), "CVE-TEST-1"])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "Models: 2" in out or "Models: 2" in out
    assert "model-alpha" in out
    assert "model-beta" in out
    assert "app-1" in out
    assert "app-2" in out
