from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from .types_risk import categorize_license


@dataclass
class ModelIssue:
    message: str
    severity: str = "medium"
    code: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass
class ModelInfo:
    identifier: str
    source: str
    license: Optional[str] = None
    last_updated: Optional[datetime] = None
    license_category: str | None = None
    base_models: List[str] = field(default_factory=list)
    fine_tuned_from: List[str] = field(default_factory=list)
    training_sources: List[str] = field(default_factory=list)
    hashes: List[str] = field(default_factory=list)
    # Optional application the model is deployed to (string name for simplicity)
    deployed_to: Optional[str] = None
    # List of artifact file paths associated with the model
    artifacts: List[str] = field(default_factory=list)
    issues: List[ModelIssue] = field(default_factory=list)
    trust_signals: List[ModelIssue] = field(default_factory=list)

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

    @property
    def trust_score(self) -> int:
        score = 100
        for signal in self.trust_signals:
            if signal.severity == "high":
                score -= 15
            elif signal.severity == "medium":
                score -= 8
            else:
                score -= 4
        return max(0, score)


def apply_license_category_model(model: "ModelInfo") -> None:
    model.license_category = categorize_license(model.license)
