from __future__ import annotations

import base64
import json
from pathlib import Path


def canonical_payload(payload: dict) -> bytes:
    """Return the stable bytes that are signed/verified."""
    unsigned = dict(payload)
    unsigned.pop("signature", None)
    unsigned.pop("integrity_digest", None)
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_ed25519(payload: dict, private_key_pem: bytes) -> str:
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("cryptography is required for Ed25519 attestation signing") from exc
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(canonical_payload(payload))
    return base64.b64encode(signature).decode("ascii")


def verify_ed25519(payload: dict, signature_b64: str, public_key_pem: bytes) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("cryptography is required for Ed25519 attestation verification") from exc
    public_key = serialization.load_pem_public_key(public_key_pem)
    try:
        public_key.verify(base64.b64decode(signature_b64), canonical_payload(payload))
    except InvalidSignature:
        return False
    return True


def load_pem(path: Path) -> bytes:
    return path.read_bytes()
