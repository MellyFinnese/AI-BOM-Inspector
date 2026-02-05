from __future__ import annotations

import json
from dataclasses import asdict
from typing import Iterable

from .model_risk_db import load_threat_taxonomy_db
from .stack_discovery import MODEL_HOST_DEPENDENCIES, PROVIDER_DEPENDENCIES
from .types import CompletenessSummary, ExecutiveRiskSummary, Report, RuntimeTrace


def build_completeness(
    dependencies_count: int,
    models_count: int,
    runtime_trace: RuntimeTrace | None,
    env_vars: Iterable[str] | None = None,
) -> CompletenessSummary:
    static_total = dependencies_count + models_count
    runtime_total = 0
    if runtime_trace:
        runtime_total = len(runtime_trace.observed_dependencies) + len(runtime_trace.observed_models)

    static_coverage = 100.0 if static_total > 0 else 0.0
    runtime_coverage = 0.0
    if static_total:
        runtime_coverage = min(100.0, (runtime_total / static_total) * 100)

    unobservable = []
    if not runtime_trace:
        unobservable.append("Runtime model loading: unknown (no runtime trace supplied)")
    if env_vars:
        unobservable.append("Environment-based model selection detected; runtime resolution required")

    return CompletenessSummary(
        static_coverage_pct=round(static_coverage, 1),
        runtime_coverage_pct=round(runtime_coverage, 1),
        static_visibility=static_total > 0,
        runtime_visibility=runtime_trace is not None,
        unobservable_areas=unobservable,
    )


def build_executive_summary(report: Report) -> ExecutiveRiskSummary:
    breakdown = report.risk_breakdown
    governance_flags = breakdown.get("unpinned_deps", 0) + breakdown.get("unverified_sources", 0)
    cves = breakdown.get("cves", 0)
    unknown_licenses = breakdown.get("unknown_licenses", 0)
    stale = breakdown.get("stale_models", 0)

    if report.stack_risk_score < 50 or cves > 0:
        governance = "High"
    elif governance_flags > 0 or report.stack_risk_score < 75:
        governance = "Medium"
    else:
        governance = "Low"

    if cves > 0 or unknown_licenses > 0:
        regulatory = "High"
    elif stale > 0 or governance_flags > 0:
        regulatory = "Medium"
    else:
        regulatory = "Low"

    total_components = len(report.dependencies) + len(report.models)
    if total_components >= 50 or cves >= 3:
        blast_radius = "High"
    elif total_components >= 20 or cves >= 1:
        blast_radius = "Medium"
    else:
        blast_radius = "Low"

    rationale = []
    if governance_flags:
        rationale.append(f"{governance_flags} governance flags (unpinned deps or unverified sources)")
    if cves:
        rationale.append(f"{cves} vulnerability/advisory hits")
    if unknown_licenses:
        rationale.append(f"{unknown_licenses} unknown license items")
    if stale:
        rationale.append(f"{stale} stale model references")

    return ExecutiveRiskSummary(
        governance_risk=governance,
        regulatory_exposure=regulatory,
        supply_chain_blast_radius=blast_radius,
        rationale=rationale,
    )


def build_sbom_correlations(report: Report) -> list[dict]:
    correlations: list[dict] = []
    provider_lookup = {
        dep.name.lower(): PROVIDER_DEPENDENCIES.get(dep.name.lower())
        for dep in report.dependencies
        if PROVIDER_DEPENDENCIES.get(dep.name.lower())
    }
    host_lookup = {dep.name.lower(): MODEL_HOST_DEPENDENCIES.get(dep.name.lower()) for dep in report.dependencies}

    for model in report.models:
        supporting: list[str] = []
        for dep in report.dependencies:
            normalized = dep.name.lower()
            provider = provider_lookup.get(normalized)
            host = host_lookup.get(normalized)
            if provider and provider == model.source:
                supporting.append(dep.name)
            elif host and host == model.source:
                supporting.append(dep.name)
        if supporting:
            correlations.append(
                {
                    "model": model.identifier,
                    "source": model.source,
                    "supporting_dependencies": sorted(set(supporting)),
                }
            )

    if not correlations and (report.dependencies or report.models):
        correlations.append(
            {
                "model": "unmapped",
                "source": "unknown",
                "supporting_dependencies": [],
                "note": "No direct SBOM ↔ AI-BOM correlation detected; add runtime traces or provider metadata.",
            }
        )
    return correlations


def build_threat_summary(report: Report) -> dict | None:
    taxonomy = load_threat_taxonomy_db()
    mappings = taxonomy.get("mappings") or {}

    findings: list[dict] = []
    threat_counts: dict[str, int] = {}

    def _record(subject: str, subject_type: str, code: str, severity: str) -> None:
        mapping = mappings.get(code)
        if not mapping:
            return
        threats = mapping.get("threats") or []
        for threat in threats:
            threat_counts[threat] = threat_counts.get(threat, 0) + 1
        findings.append(
            {
                "subject": subject,
                "subject_type": subject_type,
                "issue_code": code,
                "severity": severity,
                "threats": threats,
                "stride": mapping.get("stride") or [],
                "mitre_atlas": mapping.get("mitre_atlas") or [],
            }
        )

    for dep in report.dependencies:
        for issue in dep.issues + dep.trust_signals:
            _record(dep.name, "dependency", str(issue.code or issue.message), issue.severity)

    for model in report.models:
        for issue in model.issues + model.trust_signals:
            _record(model.identifier, "model", str(issue.code or issue.message), issue.severity)

    if not findings:
        return None

    return {
        "version": taxonomy.get("version", "unknown"),
        "findings": findings,
        "threat_counts": threat_counts,
    }


def serialize_dataclass(value) -> dict | None:
    if not value:
        return None
    return json.loads(json.dumps(asdict(value), default=str))
