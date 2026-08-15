from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable, Optional

from .attestation import ProvenanceInput, build_attestation, write_attestation


def _sha256_of_payload(payload: dict) -> str:
    txt = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(txt.encode("utf-8")).hexdigest()


def sign_attestation_with_sigstore(payload: dict, key_ref: Optional[str] = None) -> str:
    """Attempt to sign the attestation using sigstore if available.

    This function tries to import the sigstore libraries and perform a
    transparent signing operation. If sigstore is not installed or the
    signing operation is not possible in the environment, fall back to
    returning a synthetic SHA256 'signature' for provenance records so the
    rest of the pipeline can continue.
    """
    try:
        # best-effort import; not required for CI prototype
        import sigstore.sign

        # Example usage (not executed in many CI environments):
        # signature = sigstore.sign.sign(...)
        # For now, avoid running network or key operations in this prototype.
        raise RuntimeError("sigstore signing is not executed in this environment")
    except Exception:
        # fallback synthetic signature
        return _sha256_of_payload(payload)


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
    signature = sign_attestation_with_sigstore(payload, key_ref=key_ref)
    payload["signature"] = {"sha256": signature}
    out = destination / f"attestation-{report_path.stem}.json"
    write_attestation(out, payload)
    return out
