from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class AuditLogEntry:
    action: str
    actor: str | None
    timestamp: str
    report_path: str | None
    report_sha256: str | None
    attestation_path: str | None
    policy_path: str | None
    approvals: list[str]
    metadata: dict


def _hash_payload(payload: dict, previous_hash: str | None) -> str:
    digest = hashlib.sha256()
    digest.update((previous_hash or "").encode())
    digest.update(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    return digest.hexdigest()


def _load_last_hash(path: Path) -> str | None:
    if not path.exists():
        return None
    last_line = None
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                last_line = line
    if not last_line:
        return None
    try:
        payload = json.loads(last_line)
    except json.JSONDecodeError:
        return None
    return payload.get("entry_hash")


def append_audit_log(path: Path, entry: AuditLogEntry) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.close(fd)
    previous_hash = _load_last_hash(path)
    payload = {
        "action": entry.action,
        "actor": entry.actor,
        "timestamp": entry.timestamp,
        "report_path": entry.report_path,
        "report_sha256": entry.report_sha256,
        "attestation_path": entry.attestation_path,
        "policy_path": entry.policy_path,
        "approvals": entry.approvals,
        "metadata": entry.metadata,
    }
    entry_hash = _hash_payload(payload, previous_hash)
    payload["previous_hash"] = previous_hash
    payload["entry_hash"] = entry_hash
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def verify_audit_log(path: Path) -> list[str]:
    errors: list[str] = []
    if not path.exists():
        return [f"Audit log not found: {path}"]
    previous_hash = None
    with path.open("r", encoding="utf-8") as handle:
        for idx, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                errors.append(f"Line {idx}: invalid JSON")
                continue
            entry_hash = payload.get("entry_hash")
            expected = _hash_payload(
                {
                    "action": payload.get("action"),
                    "actor": payload.get("actor"),
                    "timestamp": payload.get("timestamp"),
                    "report_path": payload.get("report_path"),
                    "report_sha256": payload.get("report_sha256"),
                    "attestation_path": payload.get("attestation_path"),
                    "policy_path": payload.get("policy_path"),
                    "approvals": payload.get("approvals") or [],
                    "metadata": payload.get("metadata") or {},
                },
                previous_hash,
            )
            if payload.get("previous_hash") != previous_hash:
                errors.append(f"Line {idx}: previous_hash mismatch")
            if entry_hash != expected:
                errors.append(f"Line {idx}: hash mismatch")
            previous_hash = entry_hash
    return errors


def build_audit_entry(
    *,
    action: str,
    actor: str | None,
    report_path: Path | None,
    report_sha256: str | None,
    attestation_path: Path | None,
    policy_path: Path | None,
    approvals: list[str],
    metadata: dict | None = None,
) -> AuditLogEntry:
    return AuditLogEntry(
        action=action,
        actor=actor,
        timestamp=datetime.now(timezone.utc).isoformat(),
        report_path=str(report_path) if report_path else None,
        report_sha256=report_sha256,
        attestation_path=str(attestation_path) if attestation_path else None,
        policy_path=str(policy_path) if policy_path else None,
        approvals=approvals,
        metadata=metadata or {},
    )
