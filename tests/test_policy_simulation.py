import json
from pathlib import Path

from click.testing import CliRunner

from aibom_inspector.cli import main


def test_simulate_policy_outputs_blocking_result(tmp_path: Path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        report_path = Path("report.json")
        report_path.write_text(
            json.dumps(
                {
                    "generated_at": "2024-07-01T12:00:00Z",
                    "dependencies": [
                        {
                            "name": "unpinned",
                            "version": "0.1.0",
                            "source": "pypi",
                            "issues": ["[MISSING_PIN] Dependency uses a version range"],
                        }
                    ],
                    "models": [],
                }
            )
        )

        policy_path = Path("policy.yml")
        policy_path.write_text(
            """
min_score: 50
disallow:
  - MISSING_PIN
"""
        )

        output_path = Path("simulation.json")
        result = runner.invoke(
            main,
            [
                "simulate-policy",
                "--report",
                str(report_path),
                "--policy",
                str(policy_path),
                "--output",
                str(output_path),
            ],
        )

        assert result.exit_code == 0
        payload = json.loads(output_path.read_text())
        assert payload["would_block"] is True
        assert any("MISSING_PIN" in failure for failure in payload["failures"])
