from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class DependencyIssue:
    message: str
    severity: str = "medium"


@dataclass
class DependencyInfo:
    name: str
    version: Optional[str]
    source: str
    issues: List[DependencyIssue] = field(default_factory=list)

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
class ModelIssue:
    message: str
    severity: str = "medium"


@dataclass
class ModelInfo:
    identifier: str
    source: str
    license: Optional[str] = None
    last_updated: Optional[datetime] = None
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
