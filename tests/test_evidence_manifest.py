import json
from pathlib import Path

from click.testing import CliRunner

from aibom_inspector.cli import main


def test_evidence_pack_writes_manifest_with_chain_hash(tmp_path: Path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        requirements = Path("requirements.txt")
        requirements.write_text("requests==2.32.0\n")

        evidence_dir = Path("evidence")
        result = runner.invoke(
            main,
            [
                "scan",
                "--requirements",
                str(requirements),
                "--format",
                "json",
                "--offline",
                "--evidence-pack",
                str(evidence_dir),
                "--evidence-prev-hash",
                "previous-hash",
            ],
        )

        assert result.exit_code == 0
        manifest_path = evidence_dir / "evidence-manifest.json"
        assert manifest_path.exists()
        manifest = json.loads(manifest_path.read_text())
        assert manifest["previous_hash"] == "previous-hash"
        assert "bundle_hash" in manifest
        assert "files" in manifest
        assert any(name.endswith(".json") for name in manifest["files"].keys())
