from pathlib import Path

import pytest

from aibom_inspector.attestation_sigstore import create_and_write_attestation
from aibom_inspector.parsers import ParserError, SAFE_MAX_BYTES, read_text
from aibom_inspector.trust_root import (
    create_trust_root,
    trust_root_fingerprint,
    verify_trust_root_against,
)


def test_read_text_rejects_oversized_input_before_read(tmp_path: Path):
    path = tmp_path / "oversized.json"
    path.write_bytes(b"x" * (SAFE_MAX_BYTES + 1))

    with pytest.raises(ParserError, match="safe size limit"):
        read_text(path)


def test_trust_root_requires_external_anchor_for_authenticity():
    root = create_trust_root()
    fingerprint = trust_root_fingerprint(root)

    assert verify_trust_root_against(root, fingerprint)
    assert not verify_trust_root_against(root, "0" * 64)

    # Replacing the root's secret and self-generated signature must not make
    # the replacement trusted when the deployment pins the original root.
    replacement = create_trust_root()
    assert not verify_trust_root_against(replacement, fingerprint)


def test_attestation_does_not_label_digest_as_signature(tmp_path: Path):
    report = tmp_path / "report.json"
    report.write_text("{}")

    output = create_and_write_attestation(
        destination=tmp_path,
        inputs=[],
        report_hash="abc123",
        report_path=report,
        report_format="json",
        output_hashes={},
    )

    import json

    payload = json.loads(output.read_text())
    assert payload["signature_status"] == "unsigned"
    assert payload["signature"] is None
    assert payload["integrity_digest"]["algorithm"] == "sha256"
    assert payload["integrity_digest"]["value"]
