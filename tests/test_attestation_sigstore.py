from pathlib import Path
from aibom_inspector.attestation import ProvenanceInput, compute_output_hash
from aibom_inspector.attestation_sigstore import create_and_write_attestation


def test_create_attestation(tmp_path: Path):
    inp = ProvenanceInput(path="models/model.safetensors", sha256="deadbeef")
    out = create_and_write_attestation(
        destination=tmp_path,
        inputs=[inp],
        report_hash="abcd1234",
        report_path=tmp_path / "report.json",
        report_format="cyclonedx",
        output_hashes={"bom": "beef"},
        git_commit=None,
    )
    assert out.exists()
    content = out.read_text()
    assert "attestation" in out.name
    assert "signature" in content
