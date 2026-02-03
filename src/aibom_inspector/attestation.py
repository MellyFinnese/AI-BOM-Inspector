from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

from . import __version__


@dataclass(frozen=True)
class ProvenanceInput:
    path: str
    sha256: str


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_input_hashes(paths: Iterable[Path]) -> list[ProvenanceInput]:
    entries: list[ProvenanceInput] = []
    for path in paths:
        if not path or not path.exists():
            continue
        entries.append(ProvenanceInput(path=str(path), sha256=_file_sha256(path)))
    return entries


def compute_output_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def current_git_commit(root: Path | None = None) -> str | None:
    import subprocess

    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(root) if root else None,
            check=True,
            capture_output=True,
            text=True,
        )
    except Exception:
        return None
    return result.stdout.strip()


def build_attestation(
    *,
    inputs: Iterable[ProvenanceInput],
    report_hash: str,
    report_path: Path,
    report_format: str,
    output_hashes: dict[str, str],
    git_commit: str | None,
    signature: str | None = None,
    metadata: dict | None = None,
) -> dict:
    payload = {
        "generated_at": datetime.utcnow().isoformat(),
        "tool": {"name": "aibom-inspector", "version": __version__},
        "git_commit": git_commit,
        "inputs": [entry.__dict__ for entry in inputs],
        "report": {
            "path": str(report_path),
            "format": report_format,
            "sha256": report_hash,
        },
        "outputs": output_hashes,
    }
    if signature:
        payload["signature"] = {"sha256": signature}
    if metadata:
        payload["metadata"] = metadata
    return payload


def write_attestation(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))
