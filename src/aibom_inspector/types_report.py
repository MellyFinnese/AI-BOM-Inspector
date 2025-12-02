from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .policy_graph import GraphPolicyViolation, GraphSnapshot
from .types_dependencies import DependencyInfo
from .types_models import ModelInfo
from .types_risk import RiskSettings


@dataclass
class Report:
    dependencies: list[DependencyInfo]
    models: list[ModelInfo]
    generated_at: datetime
    ai_summary: Optional[str] = None
    risk_settings: RiskSettings = field(default_factory=RiskSettings)
    stack_snapshot: GraphSnapshot | None = None
    graph_policy_violations: list[GraphPolicyViolation] = field(default_factory=list)

    @property
    def total_risk(self) -> int:
        return sum(dep.risk_score for dep in self.dependencies) + sum(
            model.risk_score for model in self.models
        )

    @property
    def stack_risk_score(self) -> int:
        """Return an easy-to-share 0–100 risk score (100 = healthiest)."""

        penalties = 0
        for dep in self.dependencies:
            for dep_issue in dep.issues:
                penalties += self.risk_settings.penalty_for(dep_issue.severity)

        for model in self.models:
            for model_issue in model.issues:
                penalties += self.risk_settings.penalty_for(model_issue.severity)

        breakdown = self.risk_breakdown
        penalties += self.risk_settings.governance_penalty * (
            breakdown.get("unpinned_deps", 0) + breakdown.get("unverified_sources", 0)
        )
        penalties += self.risk_settings.cve_penalty * breakdown.get("cves", 0)

        return max(0, min(self.risk_settings.max_score, self.risk_settings.max_score - penalties))

    @property
    def risk_breakdown(self) -> dict[str, int]:
        """Summarize core AI-BOM risk categories for dashboards/CI."""

        buckets = {
            "unpinned_deps": 0,
            "unverified_sources": 0,
            "unknown_licenses": 0,
            "stale_models": 0,
            "cves": 0,
        }

        for dep in self.dependencies:
            for dep_issue in dep.issues:
                code = dep_issue.code or dep_issue.message
                if code and any(token in str(code) for token in {"MISSING_PIN", "LOOSE_PIN"}):
                    buckets["unpinned_deps"] += 1
                if code and "CVE" in str(code).upper():
                    buckets["cves"] += 1
                elif "[CVE]" in dep_issue.message or "[KNOWN_VULN]" in dep_issue.message:
                    buckets["cves"] += 1
            if dep.license_category == "unknown" and dep.license:
                buckets["unknown_licenses"] += 1

        for model in self.models:
            for model_issue in model.issues:
                code = model_issue.code or model_issue.message
                if code and "UNVERIFIED_SOURCE" in str(code):
                    buckets["unverified_sources"] += 1
                if code and "UNKNOWN_LICENSE" in str(code):
                    buckets["unknown_licenses"] += 1
                if code and "STALE_MODEL" in str(code):
                    buckets["stale_models"] += 1
                if code and "CVE" in str(code).upper():
                    buckets["cves"] += 1
                elif "[CVE]" in model_issue.message or "[KNOWN_VULN]" in model_issue.message:
                    buckets["cves"] += 1
            if model.license_category == "unknown" and model.license:
                buckets["unknown_licenses"] += 1

        return buckets
