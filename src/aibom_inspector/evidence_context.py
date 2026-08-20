from __future__ import annotations

from pathlib import Path
from typing import Literal

EvidenceContext = Literal[
    "production",
    "implementation",
    "test",
    "benchmark",
    "documentation",
    "example",
    "unknown",
]


_BENCHMARK_PARTS = {"benchmark", "benchmarks", "ground_truth", "ground-truth"}
_TEST_PARTS = {"test", "tests", "fixture", "fixtures"}
_DOC_PARTS = {"doc", "docs", "documentation"}
_EXAMPLE_PARTS = {"example", "examples", "demo", "demos"}


def classify_evidence_context(path: str | Path) -> EvidenceContext:
    """Classify where model evidence came from without judging its content.

    The classifier is intentionally conservative: benchmark, test, documentation,
    and example evidence is never treated as production-relevant. Unknown paths
    remain ``unknown`` rather than being promoted silently.
    """
    raw = str(path).replace("\\", "/").strip("/")
    if not raw:
        return "unknown"

    parts = [part.lower() for part in Path(raw).parts]
    filename = parts[-1]
    stem = filename.rsplit(".", 1)[0]

    if any(part in _BENCHMARK_PARTS for part in parts):
        return "benchmark"
    if any(part in _TEST_PARTS for part in parts) or stem.startswith("test_"):
        return "test"
    if any(part in _DOC_PARTS for part in parts) or filename.lower().endswith((".md", ".rst")):
        return "documentation"
    if any(part in _EXAMPLE_PARTS for part in parts):
        return "example"

    # Internal implementation paths should not be promoted into an application's
    # production inventory when a project scans its own tooling/analysis code.
    implementation_markers = {
        "detectors",
        "collector",
        "collectors",
        "risk",
        "compliance",
        "report",
        "export",
        "resolvers",
        "models",
    }
    if any(part in implementation_markers for part in parts):
        return "implementation"

    # Source/configuration files without a stronger contextual marker are treated
    # as potentially production-relevant rather than guessed as non-production.
    if parts and parts[-1] in {"pyproject.toml", "package.json", "requirements.txt", "uv.lock"}:
        return "production"
    if Path(raw).suffix.lower() in {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".yaml", ".yml", ".toml", ".env", ".env.example"}:
        return "production"

    return "unknown"


def production_relevance(context: EvidenceContext) -> bool:
    return context == "production"
