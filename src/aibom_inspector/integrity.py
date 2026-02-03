from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from .types import IntegrityFinding


LOCKFILE_NAMES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "Pipfile.lock",
    "requirements.lock",
    "go.sum",
    "Cargo.lock",
    "composer.lock",
}


@dataclass(frozen=True)
class HashExpectation:
    path: Path
    sha256: str


def compute_file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_expected_hashes(
    expected: Mapping[Path, str],
    *,
    kind: str,
    code_prefix: str,
) -> list[IntegrityFinding]:
    findings: list[IntegrityFinding] = []
    for path, expected_hash in expected.items():
        if not path.exists():
            findings.append(
                IntegrityFinding(
                    kind=kind,
                    path=str(path),
                    message=f"{kind.title()} file missing: {path}",
                    severity="high",
                    code=f"{code_prefix}_MISSING",
                )
            )
            continue
        actual = compute_file_sha256(path)
        if actual != expected_hash:
            findings.append(
                IntegrityFinding(
                    kind=kind,
                    path=str(path),
                    message=f"{kind.title()} checksum mismatch for {path}",
                    severity="high",
                    code=f"{code_prefix}_CHECKSUM_MISMATCH",
                )
            )
    return findings


def find_lockfiles(root: Path) -> list[Path]:
    lockfiles: list[Path] = []
    for name in LOCKFILE_NAMES:
        lockfiles.extend(root.rglob(name))
    return lockfiles


def enforce_lockfile_checksums(
    root: Path,
    expected: Mapping[Path, str],
    *,
    require_all: bool,
) -> list[IntegrityFinding]:
    findings = verify_expected_hashes(expected, kind="lockfile", code_prefix="LOCKFILE")
    if require_all:
        expected_paths = {path.resolve() for path in expected}
        for lockfile in find_lockfiles(root):
            if lockfile.resolve() not in expected_paths:
                findings.append(
                    IntegrityFinding(
                        kind="lockfile",
                        path=str(lockfile),
                        message=f"Lockfile checksum missing for {lockfile}",
                        severity="high",
                        code="LOCKFILE_CHECKSUM_MISSING",
                    )
                )
    return findings
