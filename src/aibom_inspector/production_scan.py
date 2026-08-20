from __future__ import annotations

from pathlib import Path

from .model_inspector import _analyze_artifacts
from .production_runtime import ResourceLimits, fingerprint


def inspect_model_artifact(path: Path) -> dict:
    """Inspect one model artifact with bounded memory semantics.

    Tensor inspection samples bounded windows rather than materializing the full artifact;
    the runtime wrapper separately enforces byte, item, concurrency and timeout budgets.
    """
    path = path.resolve()
    artifact_kind = path.suffix.lower().lstrip(".") or "unknown"
    hashes, issues, trust = _analyze_artifacts([{"path": str(path), "kind": artifact_kind}], [])
    return {
        "path": str(path),
        "kind": artifact_kind,
        "hashes": sorted(set(hashes)),
        "issues": [issue.__dict__ for issue in issues],
        "trust_signals": [signal.__dict__ for signal in trust],
    }


def fingerprint_artifact(path: Path, *, max_bytes: int = 16 * 1024**3) -> dict:
    fp = fingerprint(path, limits=ResourceLimits(max_artifact_bytes=max_bytes))
    return fp.__dict__
