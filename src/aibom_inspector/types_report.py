from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List

from .policy_graph import GraphPolicyViolation, GraphSnapshot
from .types_dependencies import DependencyInfo
from .types_models import ModelInfo
from .types_risk import RiskSettings


@dataclass
class IntegrityFinding:
    kind: str
    path: str
    message: str
    severity: str = "high"
    code: str | None = None


@dataclass
class Application:
    name: str
    environment: Optional[str] = None
    criticality: Optional[str] = None
    data_sensitivity: Optional[str] = None
    owner: Optional[str] = None


@dataclass
class Owner:
    name: str
    contact: Optional[str] = None


@dataclass
class Report:
    dependencies: list[DependencyInfo]
    models: list[ModelInfo]
    generated_at: datetime
    applications: list[Application] = field(default_factory=list)
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
    score: int | None = None

    @property
    def total_risk(self) -> int:
        return sum(dep.risk_score for dep in self.dependencies) + sum(
            model.risk_score for model in self.models
        )

    @property
    def stack_risk_score(self) -> int:
        """Return an easy-to-share 0–100 risk score (100 = healthiest)."""

        if self.score is not None:
            return self.score
        total_penalty = min(self.total_risk, self.risk_settings.max_score)
        return max(0, self.risk_settings.max_score - total_penalty)

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
