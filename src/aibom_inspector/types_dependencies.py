from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .types_risk import categorize_license


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
    trust_signals: List[DependencyIssue] = field(default_factory=list)

    @property
    def trust_score(self) -> int:
        """Return a coarse trustworthiness score (100 = trustworthy).

        The score is intentionally simple: each trust signal subtracts a small
        amount based on severity, capping at zero. This is separate from the
        risk score to keep governance and provenance heuristics visible without
        double-counting in the main stack health score.
        """

        score = 100
        for signal in self.trust_signals:
            if signal.severity == "high":
                score -= 15
            elif signal.severity == "medium":
                score -= 8
            else:
                score -= 4
        return max(0, score)

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


def apply_license_category_dependency(dep: "DependencyInfo") -> None:
    dep.license_category = categorize_license(dep.license)
