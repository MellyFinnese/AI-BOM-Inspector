from __future__ import annotations

import hashlib
import json
import os
import platform
import resource
import tempfile
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Lock
from typing import Callable, Iterable, TypeVar

T = TypeVar("T")


class ResourceLimitExceeded(RuntimeError):
    """Raised when an artifact exceeds a configured resource budget."""


class ScanTimeout(TimeoutError):
    """Raised when a scan exceeds its configured timeout."""


@dataclass(frozen=True)
class ResourceLimits:
    max_artifact_bytes: int = 16 * 1024**3
    max_items: int = 2_000_000
    timeout_seconds: float = 900.0
    max_workers: int = min(32, (os.cpu_count() or 2) + 4)
    chunk_bytes: int = 1024 * 1024

    def validate(self) -> None:
        if self.max_artifact_bytes <= 0:
            raise ValueError("max_artifact_bytes must be positive")
        if self.max_items <= 0:
            raise ValueError("max_items must be positive")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_workers <= 0:
            raise ValueError("max_workers must be positive")
        if self.chunk_bytes <= 0:
            raise ValueError("chunk_bytes must be positive")


@dataclass(frozen=True)
class ArtifactFingerprint:
    path: str
    size: int
    mtime_ns: int
    sha256: str


@dataclass(frozen=True)
class ArtifactScanResult:
    fingerprint: ArtifactFingerprint
    result: object | None
    cached: bool
    elapsed_seconds: float


@dataclass(frozen=True)
class RuntimeProfile:
    elapsed_seconds: float
    peak_rss_bytes: int | None
    cpu_seconds: float | None
    platform: str
    python: str


def sha256_stream(path: Path, *, chunk_bytes: int = 1024 * 1024, max_bytes: int | None = None) -> str:
    """Hash arbitrarily large artifacts without loading them into memory."""
    path = path.resolve()
    digest = hashlib.sha256()
    read_total = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_bytes)
            if not chunk:
                break
            read_total += len(chunk)
            if max_bytes is not None and read_total > max_bytes:
                raise ResourceLimitExceeded(f"{path} exceeded {max_bytes} bytes while reading")
            digest.update(chunk)
    return digest.hexdigest()


def fingerprint(path: Path, *, limits: ResourceLimits | None = None) -> ArtifactFingerprint:
    limits = limits or ResourceLimits()
    limits.validate()
    path = path.resolve()
    stat = path.stat()
    if stat.st_size > limits.max_artifact_bytes:
        raise ResourceLimitExceeded(f"{path} is {stat.st_size} bytes; limit is {limits.max_artifact_bytes}")
    return ArtifactFingerprint(
        path=str(path),
        size=stat.st_size,
        mtime_ns=stat.st_mtime_ns,
        sha256=sha256_stream(path, chunk_bytes=limits.chunk_bytes, max_bytes=limits.max_artifact_bytes),
    )


class CheckpointStore:
    """Crash-safe JSON checkpoint store using fsync + atomic replace."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()

    def _path(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode()).hexdigest()
        return self.directory / f"{digest}.json"

    def load(self, key: str) -> dict | None:
        path = self._path(key)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def save(self, key: str, payload: dict) -> None:
        path = self._path(key)
        with self._lock:
            fd, tmp_name = tempfile.mkstemp(prefix=".checkpoint-", dir=self.directory, text=True)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, sort_keys=True, separators=(",", ":"), default=str)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp_name, path)
            finally:
                try:
                    os.unlink(tmp_name)
                except FileNotFoundError:
                    pass


def run_with_timeout(fn: Callable[[], T], timeout_seconds: float) -> T:
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="aibom-timeout") as pool:
        future: Future[T] = pool.submit(fn)
        try:
            return future.result(timeout=timeout_seconds)
        except TimeoutError as exc:
            future.cancel()
            raise ScanTimeout(f"scan exceeded {timeout_seconds:.2f}s") from exc


def scan_many(
    paths: Iterable[Path],
    scanner: Callable[[Path], T],
    *,
    limits: ResourceLimits | None = None,
    checkpoint_dir: Path | None = None,
) -> tuple[ArtifactScanResult, ...]:
    """Run bounded concurrent scans with deterministic output and crash recovery."""
    limits = limits or ResourceLimits()
    limits.validate()
    path_list = sorted({Path(path).resolve() for path in paths}, key=str)
    if len(path_list) > limits.max_items:
        raise ResourceLimitExceeded(f"{len(path_list)} artifacts exceed item limit {limits.max_items}")
    checkpoints = CheckpointStore(checkpoint_dir) if checkpoint_dir else None

    def worker(path: Path) -> ArtifactScanResult:
        started = time.monotonic()
        fp = fingerprint(path, limits=limits)
        key = f"{fp.path}:{fp.size}:{fp.mtime_ns}:{fp.sha256}"
        if checkpoints:
            cached = checkpoints.load(key)
            if cached and cached.get("status") == "complete":
                return ArtifactScanResult(fp, cached.get("result"), True, float(cached.get("elapsed_seconds", 0.0)))
        result = run_with_timeout(lambda: scanner(path), limits.timeout_seconds)
        elapsed = time.monotonic() - started
        if checkpoints:
            checkpoints.save(
                key,
                {
                    "status": "complete",
                    "fingerprint": asdict(fp),
                    "result": result if isinstance(result, (str, int, float, bool, list, dict, type(None))) else repr(result),
                    "elapsed_seconds": elapsed,
                },
            )
        return ArtifactScanResult(fp, result, False, elapsed)

    with ThreadPoolExecutor(max_workers=limits.max_workers, thread_name_prefix="aibom-scan") as pool:
        futures = [pool.submit(worker, path) for path in path_list]
        results = [future.result() for future in as_completed(futures)]
    return tuple(sorted(results, key=lambda item: item.fingerprint.path))


def profile(fn: Callable[[], T]) -> tuple[T, RuntimeProfile]:
    started = time.perf_counter()
    start_usage = resource.getrusage(resource.RUSAGE_SELF)
    result = fn()
    elapsed = time.perf_counter() - started
    end_usage = resource.getrusage(resource.RUSAGE_SELF)
    peak_rss_bytes: int | None = None
    if hasattr(end_usage, "ru_maxrss"):
        factor = 1024 if platform.system() != "Darwin" else 1
        peak_rss_bytes = int(end_usage.ru_maxrss * factor)
    cpu_seconds = (end_usage.ru_user + end_usage.ru_system) - (start_usage.ru_user + start_usage.ru_system)
    return result, RuntimeProfile(
        elapsed_seconds=elapsed,
        peak_rss_bytes=peak_rss_bytes,
        cpu_seconds=cpu_seconds,
        platform=platform.platform(),
        python=platform.python_version(),
    )
