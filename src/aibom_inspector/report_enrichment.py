from __future__ import annotations

import json
from dataclasses import asdict
from typing import Iterable

from .model_risk_db import load_threat_taxonomy_db
from .stack_discovery import MODEL_HOST_DEPENDENCIES, PROVIDER_DEPENDENCIES
from .types import CompletenessSummary, ExecutiveRiskSummary, Report, RuntimeTrace
from .types_risk import temporal_multiplier


def build_model_metadata_summary(report: Report) -> dict[str, int]:
    missing_lineage = 0
    missing_training = 0
    license_ambiguity = 0
    risk_profiles = 0

    for model in report.models:
        if not (model.base_models or model.fine_tuned_from):
            missing_lineage += 1
        if not model.training_sources:
            missing_training += 1
        if not model.license or model.license_category == "unknown":
            license_ambiguity += 1
        if any(issue.code and str(issue.code).startswith("MODEL_") for issue in model.issues):
            risk_profiles += 1

    return {
        "models_total": len(report.models),
        "lineage_missing": missing_lineage,
        "training_data_missing": missing_training,
        "license_ambiguity": license_ambiguity,
        "risk_profiles_flagged": risk_profiles,
    }


def build_score_explanation(report: Report) -> dict:
    breakdown = report.risk_breakdown
    settings = report.risk_settings

    issue_contributions: list[dict] = []
    for dep in report.dependencies:
        for issue in dep.issues:
            temporal = round(
                settings.penalty_for(issue.severity)
                * (temporal_multiplier(issue.metadata, settings.temporal_multipliers) - 1)
            )
            issue_contributions.append(
                {
                    "type": "dependency_issue",
                    "subject": dep.name,
                    "severity": issue.severity,
                    "code": issue.code,
                    "base_penalty": settings.penalty_for(issue.severity),
                    "temporal_penalty": temporal,
                    "metadata": issue.metadata,
                }
            )

    for model in report.models:
        for issue in model.issues:
            temporal = round(
                settings.penalty_for(issue.severity)
                * (temporal_multiplier(issue.metadata, settings.temporal_multipliers) - 1)
            )
            issue_contributions.append(
                {
                    "type": "model_issue",
                    "subject": model.identifier,
                    "severity": issue.severity,
                    "code": issue.code,
                    "base_penalty": settings.penalty_for(issue.severity),
                    "temporal_penalty": temporal,
                    "metadata": issue.metadata,
                }
            )

    missing_intel: list[dict] = []
    for model in report.models:
        if not (model.base_models or model.fine_tuned_from):
            missing_intel.append({"model": model.identifier, "signal": "lineage"})
        if not model.training_sources:
            missing_intel.append({"model": model.identifier, "signal": "training_data"})
        if not model.license or model.license_category == "unknown":
            missing_intel.append({"model": model.identifier, "signal": "license"})

    category_weights = [
        {"category": key, "weight": value, "count": breakdown.get(key, 0)}
        for key, value in settings.category_weights.items()
    ]
    org_weights = [
        {"category": key, "weight": value, "count": breakdown.get(key, 0)}
        for key, value in settings.org_weights.items()
    ]

    total_penalty = report.risk_settings.max_score - report.stack_risk_score

    nodes = [{"id": "score", "label": "stack_risk_score", "value": report.stack_risk_score}]
    edges = []
    for contribution in issue_contributions:
        node_id = f"{contribution['type']}:{contribution['subject']}:{contribution.get('code')}"
        nodes.append(
            {
                "id": node_id,
                "label": contribution["subject"],
                "type": contribution["type"],
                "severity": contribution["severity"],
                "penalty": contribution["base_penalty"] + contribution["temporal_penalty"],
            }
        )
        edges.append({"from": node_id, "to": "score", "penalty": contribution["base_penalty"]})

    for item in missing_intel:
        node_id = f"missing:{item['model']}:{item['signal']}"
        nodes.append({"id": node_id, "label": item["model"], "type": "missing_intel"})
        edges.append({"from": node_id, "to": "score", "penalty": settings.missing_intel_penalty})

    return {
        "final_score": report.stack_risk_score,
        "total_penalty": total_penalty,
        "severity_penalties": settings.severity_penalties,
        "temporal_multipliers": settings.temporal_multipliers,
        "missing_intel_penalty": settings.missing_intel_penalty,
        "category_weights": category_weights,
        "org_weights": org_weights,
        "weight_scale": settings.weight_scale,
        "issue_contributions": issue_contributions,
        "missing_intel": missing_intel,
        "policy_metadata": report.policy_metadata,
        "intel_versions": report.intel_versions,
        "graph": {"nodes": nodes, "edges": edges},
    }


def build_model_metadata_summary(report: Report) -> dict[str, int]:
    missing_lineage = 0
    missing_training = 0
    license_ambiguity = 0
    risk_profiles = 0

    for model in report.models:
        if not (model.base_models or model.fine_tuned_from):
            missing_lineage += 1
        if not model.training_sources:
            missing_training += 1
        if not model.license or model.license_category == "unknown":
            license_ambiguity += 1
        if any(issue.code and str(issue.code).startswith("MODEL_") for issue in model.issues):
            risk_profiles += 1

    return {
        "models_total": len(report.models),
        "lineage_missing": missing_lineage,
        "training_data_missing": missing_training,
        "license_ambiguity": license_ambiguity,
        "risk_profiles_flagged": risk_profiles,
    }




def build_model_metadata_summary(report: Report) -> dict[str, int]:
    missing_lineage = 0
    missing_training = 0
    license_ambiguity = 0
    risk_profiles = 0

    for model in report.models:
        if not (model.base_models or model.fine_tuned_from):
            missing_lineage += 1
        if not model.training_sources:
            missing_training += 1
        if not model.license or model.license_category == "unknown":
            license_ambiguity += 1
        if any(issue.code and str(issue.code).startswith("MODEL_") for issue in model.issues):
            risk_profiles += 1

    return {
        "models_total": len(report.models),
        "lineage_missing": missing_lineage,
        "training_data_missing": missing_training,
        "license_ambiguity": license_ambiguity,
        "risk_profiles_flagged": risk_profiles,
    }




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


def build_ai_summary(report: Report) -> str:
    breakdown = report.risk_breakdown
    model_metadata = build_model_metadata_summary(report)
    severity_counts = {"high": 0, "medium": 0, "low": 0}

    for dep in report.dependencies:
        for issue in dep.issues:
            severity = issue.severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts["low"] += 1

    for model in report.models:
        for issue in model.issues:
            severity = issue.severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts["low"] += 1

    summary_parts = [
        (
            "Stack risk score "
            f"{report.stack_risk_score}/100 across {len(report.dependencies)} dependencies "
            f"and {len(report.models)} models."
        ),
        (
            "Findings: "
            f"{severity_counts['high']} high, {severity_counts['medium']} medium, "
            f"{severity_counts['low']} low severity issues; "
            f"{breakdown.get('cves', 0)} CVE/advisory hits."
        ),
        (
            "Governance signals: "
            f"{breakdown.get('unpinned_deps', 0)} unpinned deps, "
            f"{breakdown.get('unverified_sources', 0)} unverified sources, "
            f"{breakdown.get('unknown_licenses', 0)} unknown licenses, "
            f"{breakdown.get('stale_models', 0)} stale models."
        ),
    ]

    if report.completeness:
        summary_parts.append(
            (
                "Visibility: "
                f"{report.completeness.static_coverage_pct}% static coverage, "
                f"{report.completeness.runtime_coverage_pct}% runtime coverage."
            )
        )

    if report.integrity_findings:
        summary_parts.append(
            f"Integrity checks: {len(report.integrity_findings)} finding(s) flagged."
        )

    if report.models:
        summary_parts.append(
            "Model metadata coverage: "
            f"{model_metadata['lineage_missing']} missing lineage, "
            f"{model_metadata['training_data_missing']} missing training provenance, "
            f"{model_metadata['license_ambiguity']} license ambiguities."
        )

    return " ".join(summary_parts)


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
