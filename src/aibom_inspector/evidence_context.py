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
    """Classify model evidence by repository context.

    Known non-production contexts are explicitly marked so inventory can retain
    them without promoting them into production risk.
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

    implementation_markers = {
        "detectors",
        "collector",
        "collectors",
        "risk",
        "compliance",
        "report",
        "export",
        "resolvers",
    }
    if any(part in implementation_markers for part in parts):
        return "implementation"

    if filename.lower() in {"pyproject.toml", "package.json", "requirements.txt", "uv.lock"}:
        return "production"
    if Path(raw).suffix.lower() in {
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".env",
        ".env.example",
    }:
        return "production"

    return "unknown"


def production_relevance(context: EvidenceContext) -> bool:
    return context == "production"
