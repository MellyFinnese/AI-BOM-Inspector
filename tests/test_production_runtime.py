from __future__ import annotations

import time
from pathlib import Path

import pytest

from aibom_inspector.production_runtime import (
    ResourceLimitExceeded,
    ResourceLimits,
    ScanTimeout,
    scan_many,
    sha256_stream,
)


def test_large_file_hash_is_streamed(tmp_path: Path) -> None:
    path = tmp_path / "artifact.bin"
    path.write_bytes(b"x" * (3 * 1024 * 1024))
    assert len(sha256_stream(path, chunk_bytes=64 * 1024)) == 64


def test_resource_limit_is_enforced_before_scan(tmp_path: Path) -> None:
    path = tmp_path / "artifact.bin"
    path.write_bytes(b"x" * 1024)
    with pytest.raises(ResourceLimitExceeded):
        scan_many([path], lambda p: p.stat().st_size, limits=ResourceLimits(max_artifact_bytes=100))


def test_concurrent_scan_is_deterministic_and_resumable(tmp_path: Path) -> None:
    paths = []
    for name in ("b.bin", "a.bin", "c.bin"):
        path = tmp_path / name
        path.write_bytes(name.encode() * 1024)
        paths.append(path)

    checkpoint = tmp_path / "checkpoints"
    calls: list[str] = []

    def scanner(path: Path) -> str:
        calls.append(path.name)
        return sha256_stream(path)

    first = scan_many(paths, scanner, checkpoint_dir=checkpoint, limits=ResourceLimits(max_workers=3))
    first_hashes = [item.result for item in first]
    assert [item.fingerprint.path for item in first] == sorted(item.fingerprint.path for item in first)
    assert all(not item.cached for item in first)

    second = scan_many(paths, scanner, checkpoint_dir=checkpoint, limits=ResourceLimits(max_workers=3))
    assert [item.result for item in second] == first_hashes
    assert all(item.cached for item in second)
    assert len(calls) == 3


def test_incremental_mode_skips_rehash_for_unchanged_artifact(tmp_path: Path) -> None:
    path = tmp_path / "artifact.bin"
    path.write_bytes(b"stable" * 2048)
    checkpoint = tmp_path / "checkpoints"
    calls = 0

    def scanner(_: Path) -> str:
        nonlocal calls
        calls += 1
        return "scanned"

    limits = ResourceLimits(max_workers=1, incremental=True)
    first = scan_many([path], scanner, checkpoint_dir=checkpoint, limits=limits)
    second = scan_many([path], scanner, checkpoint_dir=checkpoint, limits=limits)
    assert not first[0].cached
    assert second[0].cached
    assert calls == 1


def test_timeout_is_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "slow.bin"
    path.write_bytes(b"slow")

    def slow(_: Path) -> str:
        time.sleep(0.2)
        return "done"

    with pytest.raises(ScanTimeout):
        scan_many([path], slow, limits=ResourceLimits(timeout_seconds=0.01))
