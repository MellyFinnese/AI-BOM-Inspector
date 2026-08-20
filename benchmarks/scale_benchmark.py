from __future__ import annotations

import argparse
import json
import tempfile
import time
from pathlib import Path

from aibom_inspector.production_runtime import ResourceLimits, profile, scan_many, sha256_stream


def build_fixture(directory: Path, artifacts: int, bytes_per_artifact: int) -> list[Path]:
    paths: list[Path] = []
    payload = b"AIBOM" * max(1, bytes_per_artifact // 5)
    payload = payload[:bytes_per_artifact]
    for index in range(artifacts):
        path = directory / f"artifact-{index:06d}.bin"
        path.write_bytes(payload)
        paths.append(path)
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark bounded concurrent artifact scanning.")
    parser.add_argument("--artifacts", type=int, default=1000)
    parser.add_argument("--bytes-per-artifact", type=int, default=1024 * 1024)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()

    if args.artifacts <= 0 or args.bytes_per_artifact <= 0:
        raise SystemExit("artifact counts and sizes must be positive")

    with tempfile.TemporaryDirectory(prefix="aibom-scale-") as tmp:
        root = Path(tmp)
        paths = build_fixture(root, args.artifacts, args.bytes_per_artifact)
        limits = ResourceLimits(
            max_workers=args.workers,
            max_items=args.artifacts,
            max_artifact_bytes=args.bytes_per_artifact * 2,
        )

        _, metrics = profile(
            lambda: scan_many(paths, sha256_stream, limits=limits, checkpoint_dir=root / "checkpoints")
        )
        total_bytes = args.artifacts * args.bytes_per_artifact
        throughput_mib_s = total_bytes / (1024 * 1024) / max(metrics.elapsed_seconds, 1e-9)
        result = {
            "schema_version": "aibom-scale-benchmark.v1",
            "artifacts": args.artifacts,
            "bytes_per_artifact": args.bytes_per_artifact,
            "total_bytes": total_bytes,
            "workers": args.workers,
            "elapsed_seconds": metrics.elapsed_seconds,
            "cpu_seconds": metrics.cpu_seconds,
            "peak_rss_bytes": metrics.peak_rss_bytes,
            "throughput_mib_s": throughput_mib_s,
            "platform": metrics.platform,
            "python": metrics.python,
            "captured_at_epoch": time.time(),
        }
        print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
