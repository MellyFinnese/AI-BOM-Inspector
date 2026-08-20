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
    category: str = "mixed"


@dataclass(frozen=True)
class Metric:
    true_positive: int
    false_positive: int
    false_negative: int

    @property
    def precision(self) -> float:
        return self.true_positive / (self.true_positive + self.false_positive) if self.true_positive + self.false_positive else 1.0

    @property
    def recall(self) -> float:
        return self.true_positive / (self.true_positive + self.false_negative) if self.true_positive + self.false_negative else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    def to_dict(self) -> dict[str, float | int]:
        return {"true_positive": self.true_positive, "false_positive": self.false_positive, "false_negative": self.false_negative, "precision": self.precision, "recall": self.recall, "f1": self.f1}


@dataclass(frozen=True)
class BenchmarkResult:
    cases: int
    true_positive: int
    false_positive: int
    false_negative: int
    precision: float
    recall: float
    f1: float
    per_detector: dict[str, Metric]
    per_category: dict[str, Metric]
    per_case: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "aibom-benchmark.v2",
            "cases": self.cases,
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "false_negative": self.false_negative,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "per_detector": {key: metric.to_dict() for key, metric in sorted(self.per_detector.items())},
            "per_category": {key: metric.to_dict() for key, metric in sorted(self.per_category.items())},
            "per_case": list(self.per_case),
        }


def load_cases(manifest: str | Path) -> tuple[BenchmarkCase, ...]:
    payload = json.loads(Path(manifest).read_text(encoding="utf-8"))
    return tuple(
        BenchmarkCase(
            name=str(item["name"]),
            path=str(item["path"]),
            expected_detectors=frozenset(str(x) for x in item.get("expected_detectors", [])),
            category=str(item.get("category", "mixed")),
        )
        for item in payload.get("cases", [])
    )


def _update(metrics: dict[str, list[int]], key: str, tp: int, fp: int, fn: int) -> None:
    values = metrics.setdefault(key, [0, 0, 0])
    values[0] += tp
    values[1] += fp
    values[2] += fn


def _freeze(metrics: dict[str, list[int]]) -> dict[str, Metric]:
    return {key: Metric(*values) for key, values in metrics.items()}


def run_benchmark(manifest: str | Path, *, root: str | Path | None = None) -> BenchmarkResult:
    manifest_path = Path(manifest).resolve()
    base = Path(root).resolve() if root else manifest_path.parent
    cases = load_cases(manifest_path)
    tp = fp = fn = 0
    detector_metrics: dict[str, list[int]] = {}
    category_metrics: dict[str, list[int]] = {}
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
        _update(category_metrics, case.category, len(hit), len(false_pos), len(false_neg))
        for detector in predicted | case.expected_detectors:
            _update(detector_metrics, detector, int(detector in hit), int(detector in false_pos), int(detector in false_neg))
        per_case.append({"name": case.name, "category": case.category, "predicted": sorted(predicted), "expected": sorted(case.expected_detectors), "true_positive": sorted(hit), "false_positive": sorted(false_pos), "false_negative": sorted(false_neg)})

    overall = Metric(tp, fp, fn)
    return BenchmarkResult(len(cases), tp, fp, fn, overall.precision, overall.recall, overall.f1, _freeze(detector_metrics), _freeze(category_metrics), tuple(per_case))
