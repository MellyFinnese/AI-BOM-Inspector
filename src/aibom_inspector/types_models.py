from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from .evidence_context import EvidenceContext, classify_evidence_context, production_relevance
from .types_risk import categorize_license


@dataclass
class ModelIssue:
    message: str
    severity: str = "medium"
    code: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Attach contextual metadata to evidence signals without changing risk."""
        if self.code != "EVIDENCE" or "evidence_context" in self.metadata:
            return
        prefix = "[EVIDENCE] discovered in "
        if prefix not in self.message:
            return
        path = self.message.split(prefix, 1)[1].strip()
        context = classify_evidence_context(path)
        self.metadata["evidence_context"] = context
        self.metadata["production_relevance"] = production_relevance(context)
        self.metadata["evidence_path"] = path


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
    def evidence_contexts(self) -> set[EvidenceContext]:
        contexts: set[EvidenceContext] = set()
        for signal in self.trust_signals:
            value = signal.metadata.get("evidence_context")
            if isinstance(value, str) and value in {
                "production",
                "implementation",
                "test",
                "benchmark",
                "documentation",
                "example",
                "unknown",
            }:
                contexts.add(value)  # type: ignore[arg-type]
        return contexts or {"unknown"}

    @property
    def primary_evidence_context(self) -> EvidenceContext:
        """Return the strongest evidence context for production-use decisions."""
        contexts = self.evidence_contexts
        priority: tuple[EvidenceContext, ...] = (
            "production",
            "test",
            "benchmark",
            "example",
            "documentation",
            "implementation",
            "unknown",
        )
        for context in priority:
            if context in contexts:
                return context
        return "unknown"

    @property
    def production_relevant(self) -> bool:
        return any(production_relevance(context) for context in self.evidence_contexts)

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
