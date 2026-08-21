from __future__ import annotations

import hashlib
import os
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


def _open_regular_file(path: Path):
    """Open a regular file without following a final symlink when supported."""
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    stat = os.fstat(fd)
    if not os.path.isfile(path) or not os.path.isfile(path.resolve()):
        os.close(fd)
        raise OSError(f"Not a regular file: {path}")
    if os.path.islink(path):
        os.close(fd)
        raise OSError(f"Symlinked files are not accepted for integrity scanning: {path}")
    return fd, stat


def compute_file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    fd, initial_stat = _open_regular_file(path)
    try:
        with os.fdopen(fd, "rb", closefd=True) as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        # A concurrent replacement cannot alter the bytes already hashed, but
        # a size change is useful evidence that a hostile workspace raced the scan.
        final_stat = path.stat()
        if final_stat.st_size != initial_stat.st_size:
            raise OSError(f"File changed during integrity scan: {path}")
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
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
        try:
            actual = compute_file_sha256(path)
        except OSError as exc:
            findings.append(
                IntegrityFinding(
                    kind=kind,
                    path=str(path),
                    message=f"{kind.title()} file could not be safely opened: {exc}",
                    severity="high",
                    code=f"{code_prefix}_UNSAFE_FILE",
                )
            )
            continue
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
