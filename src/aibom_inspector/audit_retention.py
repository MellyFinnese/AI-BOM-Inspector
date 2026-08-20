from __future__ import annotations

import gzip
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


@dataclass(frozen=True)
class AuditRetentionPolicy:
    retention_days: int = 365
    max_export_bytes: int = 512 * 1024 * 1024
    compress_exports: bool = True

    def validate(self) -> None:
        if self.retention_days <= 0:
            raise ValueError("retention_days must be positive")
        if self.max_export_bytes <= 0:
            raise ValueError("max_export_bytes must be positive")


def export_audit_log(source: Path, destination: Path, *, policy: AuditRetentionPolicy | None = None) -> Path:
    policy = policy or AuditRetentionPolicy()
    policy.validate()
    if not source.exists():
        raise FileNotFoundError(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    target = destination.with_suffix(destination.suffix + ".gz") if policy.compress_exports else destination
    writer = gzip.open if target.suffix == ".gz" else open
    written = 0
    with source.open("r", encoding="utf-8") as reader, writer(target, "wt", encoding="utf-8") as output:
        for line in reader:
            written += len(line.encode("utf-8"))
            if written > policy.max_export_bytes:
                raise ValueError("audit export exceeds configured size limit")
            output.write(line)
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    return target


def purge_audit_entries(source: Path, *, policy: AuditRetentionPolicy | None = None, now: datetime | None = None) -> int:
    policy = policy or AuditRetentionPolicy()
    policy.validate()
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=policy.retention_days)
    kept: list[str] = []
    removed = 0
    for line in source.read_text(encoding="utf-8").splitlines(keepends=True):
        try:
            import json
            payload = json.loads(line)
            timestamp = datetime.fromisoformat(str(payload.get("timestamp", "")).replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
        except Exception:
            kept.append(line)
            continue
        if timestamp >= cutoff:
            kept.append(line)
        else:
            removed += 1
    if removed:
        temporary = source.with_suffix(source.suffix + ".tmp")
        temporary.write_text("".join(kept), encoding="utf-8")
        os.replace(temporary, source)
    return removed
