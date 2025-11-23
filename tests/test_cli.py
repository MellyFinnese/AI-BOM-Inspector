import json
from pathlib import Path

from click.testing import CliRunner

from aibom_inspector.cli import main


def test_scan_cli_generates_json(tmp_path: Path):
    runner = CliRunner()
    with runner.isolated_filesystem():
        req_file = Path("requirements.txt")
        req_file.write_text("demo\n")

        result = runner.invoke(
            main,
            ["scan", "--requirements", str(req_file), "--format", "json", "--offline"],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["dependencies"][0]["name"] == "demo"
    assert payload["risk_settings"]["max_score"] == 100


def test_diff_cli_reports_changes(tmp_path: Path):
    runner = CliRunner()
    with runner.isolated_filesystem():
        base = Path("base.json")
        target = Path("target.json")

        base.write_text(json.dumps({"dependencies": [{"name": "demo", "issues": []}]}))
        target.write_text(
            json.dumps({"dependencies": [{"name": "demo", "issues": ["something"]}, {"name": "new", "issues": []}]})
        )

        result = runner.invoke(main, ["diff", str(base), str(target)])

    assert result.exit_code == 0
    assert "Added: new" in result.output
    assert "Changed risk: demo" in result.output


def test_fail_on_score_threshold(tmp_path: Path):
    runner = CliRunner()
    with runner.isolated_filesystem():
        req_file = Path("requirements.txt")
        req_file.write_text("unpinned\n")

        ok = runner.invoke(
            main,
            [
                "scan",
                "--requirements",
                str(req_file),
                "--format",
                "json",
                "--fail-on-score",
                "50",
                "--offline",
            ],
        )
        assert ok.exit_code == 0

        failing = runner.invoke(
            main,
            [
                "scan",
                "--requirements",
                str(req_file),
                "--format",
                "json",
                "--fail-on-score",
                "95",
                "--offline",
            ],
        )
        assert failing.exit_code == 1


def test_warns_when_nothing_to_scan(tmp_path: Path):
    runner = CliRunner()
    output_path = tmp_path / "report.json"
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            [
                "scan",
                "--format",
                "json",
                "--output",
                str(output_path),
                "--offline",
            ],
        )

    assert result.exit_code == 0
    assert "No dependencies or models detected; nothing to scan." in result.output
    assert output_path.exists()


def test_require_input_flag_exits_when_empty(tmp_path: Path):
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            ["scan", "--format", "json", "--offline", "--require-input"],
        )

    assert result.exit_code == 1
    assert "No dependencies or models detected; nothing to scan." in result.output
