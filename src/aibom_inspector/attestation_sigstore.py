from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable, Optional

from .attestation import ProvenanceInput, build_attestation, write_attestation


def _sha256_of_payload(payload: dict) -> str:
    txt = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(txt.encode("utf-8")).hexdigest()


def sign_attestation_with_sigstore(payload: dict, key_ref: Optional[str] = None) -> str:
    """Sign an attestation with Sigstore when a real signer is available.

    This function intentionally does not pretend that a SHA-256 digest is a
    cryptographic signature. The digest helper remains available to callers
    that need an integrity identifier, but the attestation writer records it
    separately from signature metadata.
    """
    try:
        import sigstore.sign  # type: ignore  # noqa: F401
    except ImportError as exc:
        raise RuntimeError("Sigstore signing is unavailable; no signature was produced") from exc

    # The repository currently has no configured Sigstore signing flow. Do not
    # silently manufacture a signature when the dependency is present.
    raise RuntimeError("Sigstore signing is not configured; no signature was produced")


def create_and_write_attestation(
    destination: Path,
    inputs: Iterable[ProvenanceInput],
    report_hash: str,
    report_path: Path,
    report_format: str,
    output_hashes: dict[str, str],
    git_commit: Optional[str] = None,
    key_ref: Optional[str] = None,
) -> Path:
    payload = build_attestation(
        inputs=inputs,
        report_hash=report_hash,
        report_path=report_path,
        report_format=report_format,
        output_hashes=output_hashes,
        git_commit=git_commit,
    )

    integrity_digest = _sha256_of_payload(payload)
    payload["integrity_digest"] = {"algorithm": "sha256", "value": integrity_digest}

    try:
        signature = sign_attestation_with_sigstore(payload, key_ref=key_ref)
    except RuntimeError as exc:
        payload["signature"] = None
        payload["signature_status"] = "unsigned"
        payload["signature_error"] = str(exc)
    else:
        payload["signature"] = {"algorithm": "sigstore", "value": signature}
        payload["signature_status"] = "signed"

    out = destination / f"attestation-{report_path.stem}.json"
    write_attestation(out, payload)
    return out
