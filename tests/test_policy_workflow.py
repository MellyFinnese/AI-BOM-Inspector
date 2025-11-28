import json
from pathlib import Path

from click.testing import CliRunner

from aibom_inspector.cli import main


def test_policy_gate_blocks_and_allows_exceptions(tmp_path: Path):
    runner = CliRunner()
    with runner.isolated_filesystem():
        req_file = Path("requirements.txt")
        req_file.write_text("unpinned\n")

        strict_policy = Path("policy-strict.yml")
        strict_policy.write_text("""
min_score: 95
disallow:
  - MISSING_PIN
""")

        exception_policy = Path("policy.yml")
        exception_policy.write_text("""
min_score: 50
disallow:
  - MISSING_PIN
exceptions:
  - code: MISSING_PIN
    subject: unpinned
    reason: approved breakglass
""")

        failing = runner.invoke(
            main,
            [
                "scan",
                "--requirements",
                str(req_file),
                "--format",
                "json",
                "--offline",
                "--policy",
                str(strict_policy),
            ],
        )
        assert failing.exit_code == 1

        passing = runner.invoke(
            main,
            [
                "scan",
                "--requirements",
                str(req_file),
                "--format",
                "json",
                "--offline",
                "--policy",
                str(exception_policy),
            ],
        )
    assert passing.exit_code == 0


def test_trust_signals_and_signatures(tmp_path: Path):
    runner = CliRunner()
    with runner.isolated_filesystem():
        req_file = Path("requirements.txt")
        req_file.write_text("requests==1.0.0rc1\n")

        output_path = Path("report.json")
        result = runner.invoke(
            main,
            [
                "scan",
                "--requirements",
                str(req_file),
                "--format",
                "json",
                "--output",
                str(output_path),
                "--offline",
                "--sign-report",
            ],
        )

        assert result.exit_code == 0
        payload = json.loads(output_path.read_text())
        trust_signals = payload["dependencies"][0]["trust_signals"]
        assert any("SUSPICIOUS_RELEASE" in entry["message"] for entry in trust_signals)
        assert payload["dependencies"][0]["trust_score"] < 100
        assert Path("report.json.sha256").exists()


def test_evidence_pack_includes_change_log(tmp_path: Path):
    runner = CliRunner()
    with runner.isolated_filesystem():
        baseline = Path("baseline.json")
        baseline.write_text(json.dumps({"dependencies": []}))

        req_file = Path("requirements.txt")
        req_file.write_text("demo==0.1.0\n")

        evidence_dir = Path("evidence")
        report_path = Path("report.json")

        result = runner.invoke(
            main,
            [
                "scan",
                "--requirements",
                str(req_file),
                "--format",
                "json",
                "--output",
                str(report_path),
                "--offline",
                "--baseline-report",
                str(baseline),
                "--evidence-pack",
                str(evidence_dir),
            ],
        )

        assert result.exit_code == 0
        assert (evidence_dir / report_path.name).exists()
        assert (evidence_dir / "changes-since-last-run.json").exists()
