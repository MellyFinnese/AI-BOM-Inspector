import json
from pathlib import Path

from click.testing import CliRunner

from aibom_inspector.cli import main
from aibom_inspector.trust_root import create_trust_root, verify_payload


def test_evidence_pack_signing_writes_signature_files(tmp_path: Path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        trust_root_path = Path("trust-root.json")
        trust_root = create_trust_root()
        trust_root_path.write_text(json.dumps(trust_root.as_dict(), indent=2))

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
                "--sign-evidence",
                "--trust-root",
                str(trust_root_path),
            ],
        )

        assert result.exit_code == 0
        manifest_sig = json.loads((evidence_dir / "evidence-manifest.sig.json").read_text())
        report_sig = json.loads((evidence_dir / "aibom-report.json.sig.json").read_text())

        assert manifest_sig["fingerprint"] == trust_root.fingerprint
        assert verify_payload(manifest_sig["payload"], manifest_sig["signature"], trust_root)
        assert report_sig["payload"]["kind"] == "report"
        assert verify_payload(report_sig["payload"], report_sig["signature"], trust_root)
