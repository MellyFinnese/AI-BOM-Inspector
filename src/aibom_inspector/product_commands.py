from __future__ import annotations

import json
import threading
import webbrowser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import click

from .attack_paths import discover_impact_paths
from .behavioral_drift import compare_analyses, load_analysis
from .benchmarking import run_benchmark
from .graph_payload import build_graph_payload
from .js_semantics import semantic_scan_javascript
from .production_runtime import ResourceLimits, profile, scan_many
from .production_scan import inspect_model_artifact


def register_commands(main) -> None:
    main.add_command(js_scan)
    main.add_command(attack_paths)
    main.add_command(behavior_diff)
    main.add_command(graph_export)
    main.add_command(benchmark)
    main.add_command(artifact_scan)
    main.add_command(runtime_profile)
    main.add_command(serve)


@click.command("js-scan")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "output_path", type=click.Path(dir_okay=False, writable=True, path_type=Path))
@click.option("--min-confidence", type=float, default=0.0, show_default=True)
def js_scan(path: Path, output_path: Path | None, min_confidence: float) -> None:
    """Statically inspect JavaScript/TypeScript AI usage without executing project code."""
    result = semantic_scan_javascript(path)
    payload = result.to_dict()
    if min_confidence:
        payload["findings"] = [f for f in payload["findings"] if float(f["confidence"]) >= min_confidence]
    text = json.dumps(payload, indent=2, sort_keys=True)
    if output_path:
        output_path.write_text(text + "\n", encoding="utf-8")
        click.echo(f"wrote {output_path}")
    else:
        click.echo(text)


@click.command("attack-paths")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--max-depth", type=int, default=8, show_default=True)
@click.option("--max-paths", type=int, default=100, show_default=True)
@click.option("--output", "output_path", type=click.Path(dir_okay=False, writable=True, path_type=Path))
def attack_paths(path: Path, max_depth: int, max_paths: int, output_path: Path | None) -> None:
    """Enumerate evidence-backed input-to-side-effect impact paths."""
    result = semantic_scan_javascript(path)
    payload = {
        "schema_version": "attack-paths.v1",
        "paths": [item.to_dict() for item in discover_impact_paths(result, max_depth=max_depth, max_paths=max_paths)],
    }
    text = json.dumps(payload, indent=2, sort_keys=True)
    if output_path:
        output_path.write_text(text + "\n", encoding="utf-8")
    click.echo(text)
    if payload["paths"]:
        raise click.exceptions.Exit(2)


@click.command("behavior-diff")
@click.argument("baseline", type=click.Path(exists=True, path_type=Path))
@click.argument("candidate", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "output_path", type=click.Path(dir_okay=False, writable=True, path_type=Path))
def behavior_diff(baseline: Path, candidate: Path, output_path: Path | None) -> None:
    """Compare two JS/TS scans and flag new reachable behavior paths."""
    old = load_analysis(baseline) if baseline.suffix == ".json" else semantic_scan_javascript(baseline)
    new = load_analysis(candidate) if candidate.suffix == ".json" else semantic_scan_javascript(candidate)
    payload = compare_analyses(old, new)
    text = json.dumps(payload, indent=2, sort_keys=True)
    if output_path:
        output_path.write_text(text + "\n", encoding="utf-8")
    click.echo(text)
    if payload["impact_path_added"]:
        raise click.exceptions.Exit(2)


@click.command("graph-export")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.argument("output", type=click.Path(dir_okay=False, writable=True, path_type=Path))
def graph_export(path: Path, output: Path) -> None:
    """Export the semantic JS/TS evidence graph as backend-neutral JSON."""
    result = semantic_scan_javascript(path)
    output.write_text(json.dumps(build_graph_payload(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    click.echo(f"wrote {output}")


@click.command("benchmark")
@click.argument("manifest", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--output", "output_path", type=click.Path(dir_okay=False, writable=True, path_type=Path))
@click.option("--fail-below-f1", type=float, default=0.0, show_default=True)
def benchmark(manifest: Path, root: Path | None, output_path: Path | None, fail_below_f1: float) -> None:
    """Run a reproducible precision/recall/F1 benchmark over labeled fixtures."""
    result = run_benchmark(manifest, root=root)
    text = json.dumps(result.to_dict(), indent=2, sort_keys=True)
    if output_path:
        output_path.write_text(text + "\n", encoding="utf-8")
    click.echo(text)
    if result.f1 < fail_below_f1:
        raise click.exceptions.Exit(3)


@click.command("artifact-scan")
@click.argument("paths", nargs=-1, type=click.Path(exists=True, path_type=Path))
@click.option("--workers", type=int, default=8, show_default=True)
@click.option("--timeout", "timeout_seconds", type=float, default=900.0, show_default=True)
@click.option("--max-bytes", type=int, default=16 * 1024**3, show_default=True)
@click.option("--max-items", type=int, default=2_000_000, show_default=True)
@click.option("--checkpoint-dir", type=click.Path(file_okay=False, path_type=Path))
@click.option("--incremental/--no-incremental", default=False, show_default=True)
@click.option("--rehash-cached", is_flag=True, help="Rehash unchanged inputs before reusing checkpoints.")
def artifact_scan(
    paths: tuple[Path, ...],
    workers: int,
    timeout_seconds: float,
    max_bytes: int,
    max_items: int,
    checkpoint_dir: Path | None,
    incremental: bool,
    rehash_cached: bool,
) -> None:
    """Scan model artifacts concurrently with resource limits and resumable checkpoints."""
    if not paths:
        raise click.UsageError("provide at least one artifact path")
    limits = ResourceLimits(
        max_artifact_bytes=max_bytes,
        max_items=max_items,
        timeout_seconds=timeout_seconds,
        max_workers=workers,
        incremental=incremental,
        rehash_cached=rehash_cached,
    )
    results = scan_many(paths, inspect_model_artifact, limits=limits, checkpoint_dir=checkpoint_dir)
    payload = {
        "schema_version": "artifact-scan.v1",
        "limits": {
            "max_artifact_bytes": limits.max_artifact_bytes,
            "max_items": limits.max_items,
            "timeout_seconds": limits.timeout_seconds,
            "max_workers": limits.max_workers,
            "incremental": limits.incremental,
            "rehash_cached": limits.rehash_cached,
        },
        "artifacts": [
            {
                "path": item.fingerprint.path,
                "size": item.fingerprint.size,
                "sha256": item.fingerprint.sha256,
                "cached": item.cached,
                "elapsed_seconds": item.elapsed_seconds,
                "result": item.result,
            }
            for item in results
        ],
    }
    click.echo(json.dumps(payload, indent=2, sort_keys=True))


@click.command("runtime-profile")
@click.argument("paths", nargs=-1, type=click.Path(exists=True, path_type=Path))
@click.option("--workers", type=int, default=8, show_default=True)
def runtime_profile(paths: tuple[Path, ...], workers: int) -> None:
    """Profile scalable artifact inspection for performance and memory baselines."""
    if not paths:
        raise click.UsageError("provide at least one artifact path")

    def run() -> tuple:
        limits = ResourceLimits(max_workers=workers)
        return scan_many(paths, inspect_model_artifact, limits=limits)

    result, metrics = profile(run)
    click.echo(
        json.dumps(
            {
                "schema_version": "runtime-profile.v1",
                "artifacts": len(result),
                "elapsed_seconds": metrics.elapsed_seconds,
                "cpu_seconds": metrics.cpu_seconds,
                "peak_rss_bytes": metrics.peak_rss_bytes,
                "platform": metrics.platform,
                "python": metrics.python,
            },
            indent=2,
            sort_keys=True,
        )
    )


@click.command("serve")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--port", type=int, default=8765, show_default=True)
@click.option("--open-browser/--no-browser", default=False, show_default=True)
def serve(directory: Path, port: int, open_browser: bool) -> None:
    """Serve reports and demo artifacts locally with the standard library."""
    directory = directory.resolve()
    handler = lambda *args, **kwargs: SimpleHTTPRequestHandler(*args, directory=str(directory), **kwargs)
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    url = f"http://127.0.0.1:{port}/"
    click.echo(f"serving {directory}")
    click.echo(url)
    if open_browser:
        threading.Timer(0.2, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        click.echo("stopped")
    finally:
        server.server_close()
