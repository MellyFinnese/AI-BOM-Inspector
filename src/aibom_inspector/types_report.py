from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .policy_graph import GraphPolicyViolation, GraphSnapshot
from .types_dependencies import DependencyInfo
from .types_models import ModelInfo
from .types_risk import RiskSettings, temporal_penalty


@dataclass
class IntegrityFinding:
    kind: str
    path: str
    message: str
    severity: str = "high"
    code: str | None = None


@dataclass
class Report:
    dependencies: list[DependencyInfo]
    models: list[ModelInfo]
    generated_at: datetime
    ai_summary: Optional[str] = None
    risk_settings: RiskSettings = field(default_factory=RiskSettings)
    stack_snapshot: GraphSnapshot | None = None
    graph_policy_violations: list[GraphPolicyViolation] = field(default_factory=list)
    provenance: dict | None = None
    integrity_findings: list[IntegrityFinding] = field(default_factory=list)
    approvals: list[str] = field(default_factory=list)
    runtime_trace: "RuntimeTrace | None" = None
    completeness: "CompletenessSummary | None" = None
    executive_summary: "ExecutiveRiskSummary | None" = None
    framework_mapping: dict | None = None
    policy_metadata: dict | None = None
    intel_versions: dict | None = None
    score_explanation: dict | None = None

    @property
    def total_risk(self) -> int:
        return sum(dep.risk_score for dep in self.dependencies) + sum(
            model.risk_score for model in self.models
        )

    @property
    def stack_risk_score(self) -> int:
        """Return an easy-to-share 0–100 risk score (100 = healthiest)."""

        penalties = 0
        missing_intel_hits = 0
        for dep in self.dependencies:
            for dep_issue in dep.issues:
                penalties += self.risk_settings.penalty_for(dep_issue.severity)
                penalties += temporal_penalty(dep_issue.metadata, self.risk_settings.temporal_weights)

        for model in self.models:
            for model_issue in model.issues:
                penalties += self.risk_settings.penalty_for(model_issue.severity)
                penalties += temporal_penalty(model_issue.metadata, self.risk_settings.temporal_weights)
            if not (model.base_models or model.fine_tuned_from):
                missing_intel_hits += 1
            if not model.training_sources:
                missing_intel_hits += 1
            if not model.license or model.license_category == "unknown":
                missing_intel_hits += 1

        breakdown = self.risk_breakdown
        penalties += self.risk_settings.governance_penalty * (
            breakdown.get("unpinned_deps", 0) + breakdown.get("unverified_sources", 0)
        )
        penalties += self.risk_settings.cve_penalty * breakdown.get("cves", 0)
        penalties += missing_intel_hits * self.risk_settings.missing_intel_penalty
        org_weights = self.risk_settings.org_weights
        for key, count in breakdown.items():
            if key in org_weights:
                penalties += org_weights[key] * count
        category_weights = self.risk_settings.category_weights
        if category_weights:
            weighted_total = 0.0
            for key, weight in category_weights.items():
                weighted_total += weight * breakdown.get(key, 0)
            penalties += int(self.risk_settings.weight_scale * weighted_total)

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
            "model_lineage_missing": 0,
            "training_data_missing": 0,
            "license_ambiguity": 0,
            "model_risk_profiles": 0,
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
            if not (model.base_models or model.fine_tuned_from):
                buckets["model_lineage_missing"] += 1
            if not model.training_sources:
                buckets["training_data_missing"] += 1
            if not model.license or model.license_category == "unknown":
                buckets["license_ambiguity"] += 1
            if any(
                issue.code and str(issue.code).startswith("MODEL_") for issue in model.issues
            ):
                buckets["model_risk_profiles"] += 1

        return buckets


@dataclass
class RuntimeTrace:
    trace_mode: str
    captured_at: datetime
    command: list[str]
    imported_modules: list[str] = field(default_factory=list)
    observed_models: list[str] = field(default_factory=list)
    observed_dependencies: list[str] = field(default_factory=list)
    observed_env: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class CompletenessSummary:
    static_coverage_pct: float
    runtime_coverage_pct: float
    static_visibility: bool
    runtime_visibility: bool
    unobservable_areas: list[str] = field(default_factory=list)


@dataclass
class ExecutiveRiskSummary:
    governance_risk: str
    regulatory_exposure: str
    supply_chain_blast_radius: str
    rationale: list[str] = field(default_factory=list)
