from pathlib import Path

from aibom_inspector.benchmarking import run_benchmark


def test_javascript_benchmark_is_reproducible():
    manifest = Path("benchmarks/javascript/manifest.json")
    result = run_benchmark(manifest)
    assert result.cases == 30
    assert result.precision >= 0.9
    assert result.recall >= 0.9
    assert result.f1 >= 0.9
