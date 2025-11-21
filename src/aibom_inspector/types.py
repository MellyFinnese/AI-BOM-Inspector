from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


LICENSE_CATEGORIES = {
    "gpl": "copyleft",
    "agpl": "copyleft",
    "lgpl": "weak_copyleft",
    "mpl": "weak_copyleft",
    "apache": "permissive",
    "mit": "permissive",
    "bsd": "permissive",
    "cc-by": "permissive",
}


def categorize_license(license_name: Optional[str]) -> str:
    if not license_name:
        return "unknown"

    normalized = license_name.lower()
    for token, category in LICENSE_CATEGORIES.items():
        if token in normalized:
            return category
    if "proprietary" in normalized or "custom" in normalized:
        return "proprietary"
    return "unknown"


def apply_license_category_dependency(dep: "DependencyInfo") -> None:
    dep.license_category = categorize_license(dep.license)


def apply_license_category_model(model: "ModelInfo") -> None:
    model.license_category = categorize_license(model.license)


@dataclass
class DependencyIssue:
    message: str
    severity: str = "medium"
    code: str | None = None


@dataclass
class DependencyInfo:
    name: str
    version: Optional[str]
    source: str
    license: Optional[str] = None
    issues: List[DependencyIssue] = field(default_factory=list)
    license_category: str | None = None

    @property
    def risk_score(self) -> int:
        score = 0
        for issue in self.issues:
            if issue.severity == "high":
                score += 3
            elif issue.severity == "medium":
                score += 2
            else:
                score += 1
        if self.license_category in {"copyleft", "proprietary"}:
            score += 2
        elif self.license_category == "weak_copyleft":
            score += 1
        elif self.license_category == "unknown" and self.license:
            score += 1
        return score


@dataclass
class ModelIssue:
    message: str
    severity: str = "medium"
    code: str | None = None


@dataclass
class ModelInfo:
    identifier: str
    source: str
    license: Optional[str] = None
    last_updated: Optional[datetime] = None
    license_category: str | None = None
    issues: List[ModelIssue] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        score = 0
        for issue in self.issues:
            if issue.severity == "high":
                score += 3
            elif issue.severity == "medium":
                score += 2
            else:
                score += 1
        return score


@dataclass
class Report:
    dependencies: List[DependencyInfo]
    models: List[ModelInfo]
    generated_at: datetime
    ai_summary: Optional[str] = None

    @property
    def total_risk(self) -> int:
        return sum(dep.risk_score for dep in self.dependencies) + sum(
            model.risk_score for model in self.models
        )

    @property
    def stack_risk_score(self) -> int:
        """Return an easy-to-share 0–100 risk score (100 = healthiest)."""

        severity_penalty = {"high": 10, "medium": 6, "low": 3}

        penalties = 0
        for dep in self.dependencies:
            for issue in dep.issues:
                penalties += severity_penalty.get(issue.severity, 5)

        for model in self.models:
            for issue in model.issues:
                penalties += severity_penalty.get(issue.severity, 5)

        return max(0, min(100, 100 - penalties))

    @property
    def risk_breakdown(self) -> dict[str, int]:
        """Summarize core AI-BOM risk categories for dashboards/CI."""

        buckets = {
            "unpinned_deps": 0,
            "unverified_sources": 0,
            "unknown_licenses": 0,
            "stale_models": 0,
        }

        for dep in self.dependencies:
            for issue in dep.issues:
                if "MISSING_PIN" in issue.message or "LOOSE_PIN" in issue.message:
                    buckets["unpinned_deps"] += 1
            if dep.license_category == "unknown" and dep.license:
                buckets["unknown_licenses"] += 1

        for model in self.models:
            for issue in model.issues:
                if "UNVERIFIED_SOURCE" in issue.message:
                    buckets["unverified_sources"] += 1
                if "UNKNOWN_LICENSE" in issue.message:
                    buckets["unknown_licenses"] += 1
                if "STALE_MODEL" in issue.message:
                    buckets["stale_models"] += 1
            if model.license_category == "unknown" and model.license:
                buckets["unknown_licenses"] += 1

        return buckets
