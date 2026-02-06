from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Protocol

from .types import Report
from .types_risk import temporal_multiplier


class ScoreModel(Protocol):
    name: str

    def score(self, report: Report, context: "ScoringContext") -> "ScoreOutcome":
        ...


@dataclass(frozen=True)
class OrgContext:
    asset_criticality: str
    data_sensitivity: str
    environment: str


@dataclass(frozen=True)
class ScoringContext:
    org_context: OrgContext
    policy_metadata: dict | None
    intel_versions: dict | None


@dataclass(frozen=True)
class ScoreOutcome:
    final_score: int
    total_penalty: int
    explanation: dict


_SCORE_MODELS: Dict[str, ScoreModel] = {}


def register_score_model(model: ScoreModel) -> None:
    _SCORE_MODELS[model.name] = model


def get_score_model(name: str) -> ScoreModel:
    if name not in _SCORE_MODELS:
        raise ValueError(f"Scoring model '{name}' is not registered.")
    return _SCORE_MODELS[name]


class DefaultScoreModel:
    name = "default"

    def score(self, report: Report, context: ScoringContext) -> ScoreOutcome:
        settings = report.risk_settings
        breakdown = report.risk_breakdown
        org_multiplier = _org_multiplier(settings, context.org_context)

        issue_contributions: list[dict] = []
        base_penalty = 0.0

        for dep in report.dependencies:
            for issue in dep.issues:
                severity_penalty = settings.penalty_for(issue.severity)
                multiplier = temporal_multiplier(issue.metadata, settings.temporal_multipliers)
                penalty = severity_penalty * multiplier
                base_penalty += penalty
                issue_contributions.append(
                    {
                        "type": "dependency_issue",
                        "subject": dep.name,
                        "severity": issue.severity,
                        "code": issue.code,
                        "base_penalty": severity_penalty,
                        "temporal_multiplier": multiplier,
                        "penalty": penalty,
                        "metadata": issue.metadata,
                    }
                )

        missing_intel: list[dict] = []
        for model in report.models:
            for issue in model.issues:
                severity_penalty = settings.penalty_for(issue.severity)
                multiplier = temporal_multiplier(issue.metadata, settings.temporal_multipliers)
                penalty = severity_penalty * multiplier
                base_penalty += penalty
                issue_contributions.append(
                    {
                        "type": "model_issue",
                        "subject": model.identifier,
                        "severity": issue.severity,
                        "code": issue.code,
                        "base_penalty": severity_penalty,
                        "temporal_multiplier": multiplier,
                        "penalty": penalty,
                        "metadata": issue.metadata,
                    }
                )
            if not (model.base_models or model.fine_tuned_from):
                missing_intel.append({"model": model.identifier, "signal": "lineage"})
            if not model.training_sources:
                missing_intel.append({"model": model.identifier, "signal": "training_data"})
            if not model.license or model.license_category == "unknown":
                missing_intel.append({"model": model.identifier, "signal": "license"})

        governance_penalty = settings.governance_penalty * (
            breakdown.get("unpinned_deps", 0) + breakdown.get("unverified_sources", 0)
        )
        cve_penalty = settings.cve_penalty * breakdown.get("cves", 0)
        missing_penalty = len(missing_intel) * settings.missing_intel_penalty

        category_weighted = 0.0
        for key, weight in settings.category_weights.items():
            category_weighted += weight * breakdown.get(key, 0)
        weighted_penalty = settings.weight_scale * category_weighted

        org_weighted_penalty = 0.0
        for key, value in settings.org_weights.items():
            org_weighted_penalty += value * breakdown.get(key, 0)

        total_penalty = base_penalty + governance_penalty + cve_penalty + missing_penalty
        total_penalty += weighted_penalty + org_weighted_penalty
        total_penalty = int(total_penalty * org_multiplier)

        final_score = max(0, min(settings.max_score, settings.max_score - total_penalty))

        explanation = {
            "final_score": final_score,
            "total_penalty": total_penalty,
            "org_multiplier": org_multiplier,
            "org_context": context.org_context.__dict__,
            "severity_penalties": settings.severity_penalties,
            "temporal_multipliers": settings.temporal_multipliers,
            "missing_intel_penalty": settings.missing_intel_penalty,
            "category_weights": [
                {"category": key, "weight": value, "count": breakdown.get(key, 0)}
                for key, value in settings.category_weights.items()
            ],
            "org_weights": [
                {"category": key, "weight": value, "count": breakdown.get(key, 0)}
                for key, value in settings.org_weights.items()
            ],
            "weight_scale": settings.weight_scale,
            "governance_penalty": governance_penalty,
            "cve_penalty": cve_penalty,
            "missing_intel": missing_intel,
            "issue_contributions": issue_contributions,
            "policy_metadata": context.policy_metadata,
            "intel_versions": context.intel_versions,
            "graph": _build_graph(issue_contributions, missing_intel, settings.missing_intel_penalty, final_score),
        }

        return ScoreOutcome(final_score=final_score, total_penalty=total_penalty, explanation=explanation)


def _org_multiplier(settings, context: OrgContext) -> float:
    asset_mult = settings.asset_criticality_multipliers.get(context.asset_criticality, 1.0)
    data_mult = settings.data_sensitivity_multipliers.get(context.data_sensitivity, 1.0)
    env_mult = settings.environment_multipliers.get(context.environment, 1.0)
    return asset_mult * data_mult * env_mult


def _build_graph(contributions: list[dict], missing_intel: list[dict], missing_penalty: int, score: int) -> dict:
    nodes = [{"id": "score", "label": "stack_risk_score", "value": score}]
    edges = []
    for contribution in contributions:
        node_id = f"{contribution['type']}:{contribution['subject']}:{contribution.get('code')}"
        nodes.append(
            {
                "id": node_id,
                "label": contribution["subject"],
                "type": contribution["type"],
                "severity": contribution["severity"],
                "penalty": contribution["penalty"],
            }
        )
        edges.append({"from": node_id, "to": "score", "penalty": contribution["penalty"]})

    for item in missing_intel:
        node_id = f"missing:{item['model']}:{item['signal']}"
        nodes.append({"id": node_id, "label": item["model"], "type": "missing_intel"})
        edges.append({"from": node_id, "to": "score", "penalty": missing_penalty})

    return {"nodes": nodes, "edges": edges}


register_score_model(DefaultScoreModel())
