from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .js_analysis import scan_javascript


@dataclass(frozen=True)
class BenchmarkCase:
    name: str
    path: str
    expected_detectors: frozenset[str]


@dataclass(frozen=True)
class BenchmarkResult:
    cases: int
    true_positive: int
    false_positive: int
    false_negative: int
    precision: float
    recall: float
    f1: float
    per_case: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "aibom-benchmark.v1",
            "cases": self.cases,
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "false_negative": self.false_negative,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "per_case": list(self.per_case),
        }


def load_cases(manifest: str | Path) -> tuple[BenchmarkCase, ...]:
    payload = json.loads(Path(manifest).read_text(encoding="utf-8"))
    return tuple(
        BenchmarkCase(
            name=str(item["name"]),
            path=str(item["path"]),
            expected_detectors=frozenset(str(x) for x in item.get("expected_detectors", [])),
        )
        for item in payload.get("cases", [])
    )


def run_benchmark(manifest: str | Path, *, root: str | Path | None = None) -> BenchmarkResult:
    manifest_path = Path(manifest).resolve()
    base = Path(root).resolve() if root else manifest_path.parent
    cases = load_cases(manifest_path)
    tp = fp = fn = 0
    per_case: list[dict[str, Any]] = []
    for case in cases:
        path = (base / case.path).resolve()
        result = scan_javascript(path)
        predicted = frozenset(item.detector_id for item in result.findings)
        hit = predicted & case.expected_detectors
        false_pos = predicted - case.expected_detectors
        false_neg = case.expected_detectors - predicted
        tp += len(hit)
        fp += len(false_pos)
        fn += len(false_neg)
        per_case.append({
            "name": case.name,
            "predicted": sorted(predicted),
            "expected": sorted(case.expected_detectors),
            "true_positive": sorted(hit),
            "false_positive": sorted(false_pos),
            "false_negative": sorted(false_neg),
        })
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return BenchmarkResult(len(cases), tp, fp, fn, precision, recall, f1, tuple(per_case))
