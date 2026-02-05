from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from .policy import PolicyEvaluation


ALLOWED_ASSET_TYPES = {"model", "dataset", "pipeline"}


def _hash_payload(payload: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    digest.update(json.dumps(payload, sort_keys=True).encode())
    return digest.hexdigest()


def _require(value: str | None, label: str) -> str:
    if not value:
        raise ValueError(f"{label} is required for Control Plane bundles.")
    return value


def _normalize_asset_type(value: str) -> str:
    normalized = value.lower().strip()
    if normalized not in ALLOWED_ASSET_TYPES:
        raise ValueError(f"asset_type must be one of {sorted(ALLOWED_ASSET_TYPES)}")
    return normalized


def build_control_plane_bundle(
    *,
    report: dict[str, Any],
    report_hash: str,
    org_id: str,
    project_id: str,
    environment: str,
    asset_type: str,
    asset_fingerprint: str,
    asset_id: str | None = None,
    policy_evaluation: PolicyEvaluation | None = None,
    metadata: dict[str, Any] | None = None,
    signature: str | None = None,
    attestation_path: Path | None = None,
    previous_hash: str | None = None,
) -> dict[str, Any]:
    org_id = _require(org_id, "org_id")
    project_id = _require(project_id, "project_id")
    environment = _require(environment, "environment")
    asset_fingerprint = _require(asset_fingerprint, "asset_fingerprint")
    asset_type = _normalize_asset_type(asset_type)

    decision = "unknown"
    if policy_evaluation is not None:
        decision = "pass" if policy_evaluation.passed else "fail"

    bundle = {
        "schema_version": "1.0",
        "bundle_id": str(uuid4()),
        "created_at": datetime.utcnow().isoformat(),
        "tenant": {
            "organization_id": org_id,
            "project_id": project_id,
            "environment": environment,
        },
        "asset": {
            "asset_id": asset_id,
            "type": asset_type,
            "fingerprint": asset_fingerprint,
        },
        "report": report,
        "report_sha256": report_hash,
        "policy_decision": decision,
        "policy_evaluation": policy_evaluation.as_dict() if policy_evaluation else None,
        "signature": signature,
        "attestation_path": str(attestation_path) if attestation_path else None,
        "metadata": metadata or {},
        "previous_hash": previous_hash,
    }
    bundle["bundle_hash"] = _hash_payload(bundle)
    return bundle


def write_control_plane_bundle(path: Path, bundle: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle, indent=2))
