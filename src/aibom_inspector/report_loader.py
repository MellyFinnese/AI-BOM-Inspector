from __future__ import annotations

from dataclasses import asdict
from datetime import datetime

import re

from .types_dependencies import DependencyInfo, DependencyIssue, apply_license_category_dependency
from .types_models import ModelInfo, ModelIssue, apply_license_category_model
from .types_report import Report
from .types_risk import RiskSettings
from .parsers import ReportPayloadSchema, validate_or_none


def _parse_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.utcnow()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.utcnow()


def _extract_code(message: str | None) -> str | None:
    if not message:
        return None
    match = re.match(r"\[(?P<code>[A-Z0-9_\-]+)\]", message)
    if match:
        return match.group("code")
    return None


def _parse_issue(payload: dict | str, *, issue_cls: type[DependencyIssue] | type[ModelIssue]):
    if isinstance(payload, str):
        return issue_cls(message=payload, severity="medium", code=_extract_code(payload))
    message = payload.get("message") or ""
    return issue_cls(
        message=message,
        severity=payload.get("severity") or "medium",
        code=payload.get("code") or _extract_code(message),
    )


def load_report_payload(payload: dict) -> Report:
    validated = validate_or_none(ReportPayloadSchema, payload)
    if not validated:
        raise ValueError("Invalid report payload schema.")
    payload = validated.model_dump()
    dependencies: list[DependencyInfo] = []
    for dep_payload in payload.get("dependencies", []):
        issue_details = dep_payload.get("issue_details") or dep_payload.get("issues") or []
        trust_signals = dep_payload.get("trust_signals") or []
        issues = [
            _parse_issue(entry, issue_cls=DependencyIssue)
            for entry in issue_details
        ]
        signals = [
            _parse_issue(entry, issue_cls=DependencyIssue)
            for entry in trust_signals
        ]
        dependency = DependencyInfo(
            name=dep_payload.get("name") or "unknown",
            version=dep_payload.get("version"),
            source=dep_payload.get("source") or "unknown",
            license=dep_payload.get("license"),
            registry=dep_payload.get("registry"),
            signature_verified=dep_payload.get("signature_verified"),
            issues=issues,
            trust_signals=signals,
            license_category=dep_payload.get("license_category"),
        )
        if not dependency.license_category:
            apply_license_category_dependency(dependency)
        dependencies.append(dependency)

    models: list[ModelInfo] = []
    for model_payload in payload.get("models", []):
        issue_details = model_payload.get("issue_details") or model_payload.get("issues") or []
        trust_signals = model_payload.get("trust_signals") or []
        issues = [
            _parse_issue(entry, issue_cls=ModelIssue)
            for entry in issue_details
        ]
        signals = [
            _parse_issue(entry, issue_cls=ModelIssue)
            for entry in trust_signals
        ]
        model = ModelInfo(
            identifier=model_payload.get("id") or model_payload.get("identifier") or "unknown",
            source=model_payload.get("source") or "unknown",
            license=model_payload.get("license"),
            last_updated=_parse_datetime(model_payload.get("last_updated")),
            license_category=model_payload.get("license_category"),
            base_models=model_payload.get("base_models") or [],
            fine_tuned_from=model_payload.get("fine_tuned_from") or [],
            training_sources=model_payload.get("training_sources") or [],
            hashes=model_payload.get("hashes") or [],
            issues=issues,
            trust_signals=signals,
        )
        if not model.license_category:
            apply_license_category_model(model)
        models.append(model)

    risk_payload = payload.get("risk_settings") or {}
    risk_settings = RiskSettings(
        max_score=risk_payload.get("max_score", 100),
        severity_penalties=risk_payload.get("severity_penalties", {"high": 8, "medium": 4, "low": 2}),
        governance_penalty=risk_payload.get("governance_penalty", 3),
        cve_penalty=risk_payload.get("cve_penalty", 7),
    )

    report = Report(
        dependencies=dependencies,
        models=models,
        generated_at=_parse_datetime(payload.get("generated_at")),
        ai_summary=payload.get("ai_summary"),
        risk_settings=risk_settings,
        provenance=payload.get("provenance"),
        approvals=payload.get("approvals") or [],
    )
    return report


def report_to_payload(report: Report) -> dict:
    return asdict(report)
