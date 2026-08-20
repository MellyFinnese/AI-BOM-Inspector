from __future__ import annotations

import pytest

from aibom_inspector.attestation_crypto import sign_ed25519, verify_ed25519


def test_ed25519_attestation_round_trip() -> None:
    cryptography = pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    payload = {"report_sha256": "abc", "tool": {"version": "0.2.0"}}
    signature = sign_ed25519(payload, private_pem)
    assert verify_ed25519(payload, signature, public_pem)

    payload["report_sha256"] = "tampered"
    assert not verify_ed25519(payload, signature, public_pem)
