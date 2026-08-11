from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import click

from .attestation import collect_input_hashes, compute_output_hash, current_git_commit
from .dependency_scanner import (
    enrich_with_osv,
    fetch_shadow_uefi_intel_dependency,
    parse_sbom,
    scan_go_mod,
    scan_package_json,
    scan_package_lock,
    scan_pom,
    scan_pyproject,
    scan_requirements,
)
from .framework_mapping import framework_mapping_metadata
from .graph_store import InMemoryGraphStore, populate_graph_from_report
from .integrity import enforce_lockfile_checksums, verify_expected_hashes
from .model_inspector import enrich_models_with_cves, scan_models_from_file, summarize_models
from .model_risk_db import (
    get_intel_versions,
    set_model_advisory_db_path,
    set_model_hash_db_path,
    set_threat_taxonomy_db_path,
    set_training_source_db_path,
)
from .policy import diff_reports, evaluate_policy, load_policy
from .report_enrichment import (
    build_ai_summary,
    build_completeness,
    build_executive_summary,
)
from .reporting import render_report
from .runtime_trace import load_runtime_trace
from .stack_discovery import discover_models, discover_stack
from .trust_enforcement import TrustEnforcementConfig, apply_dependency_trust_enforcement
from .types import ModelInfo, Report, RiskSettings, RuntimeTrace
from .types_risk import set_license_risk_db_path
from .parsers import ParserError, load_json_payload
from .scoring_models import OrgContext, ScoringContext, get_score_model


@dataclass(frozen=True)
class ScanConfig:
    requirements_path: Optional[str]
    pyproject_path: Optional[str]
    models_file: Optional[str]
    model_id: tuple[str, ...]
    manifest: tuple[str, ...]
    sbom_file: tuple[str, ...]
    with_cves: bool
    risk_max_score: int
    risk_penalty_high: Optional[int]
    risk_penalty_medium: Optional[int]
    risk_penalty_low: Optional[int]
    risk_penalty_governance: Optional[int]
    risk_penalty_cve: Optional[int]
    fail_on_score: Optional[int]
    include_shadow_repo: bool
    shadow_timeout: Optional[float]
    shadow_repo_url: Optional[str]
    offline: bool
    osv_url: Optional[str]
    osv_timeout: Optional[float]
    model_advisory_db: Optional[str]
    model_hash_db: Optional[str]
    threat_taxonomy_db: Optional[str]
    license_risk_db: Optional[str]
    training_source_db: Optional[str]
    require_input: bool
    approval: tuple[str, ...]
    registry_allowlist: tuple[str, ...]
    protected_namespace: tuple[str, ...]
    require_dependency_signatures: bool
    lockfile_checksum: tuple[str, ...]
    enforce_lockfile_checksums_flag: bool
    config_checksum: tuple[str, ...]
    ruleset_checksum: tuple[str, ...]
    plugin_signature: tuple[str, ...]
    discover_stack_flag: bool
    env: str
    policy: Optional[str]
    enforce_graph_policy: bool
    runtime_trace: Optional[str]
    baseline_report: Optional[str]
    ai_summary: bool
    max_manifest_bytes: Optional[int]
    org_context: OrgContext | None
    scoring_model_override: str | None


@dataclass(frozen=True)
class ScanResult:
    report: Report
    report_json: dict
    policy_evaluation: object | None
    baseline_diff: dict | None
    policy_failed: bool
    score_failed: bool
    input_hashes: list
    git_commit: str | None
    integrity_findings: list
    has_inputs: bool


def collect_dependencies(
    requirements: Optional[str],
    pyproject: Optional[str],
    extra_manifests: tuple[str, ...],
    *,
    include_shadow_repo: bool,
    shadow_timeout: Optional[float],
    shadow_repo_url: Optional[str],
    offline: bool,
    max_manifest_bytes: Optional[int],
) -> list:
    deps = []
    if requirements:
        deps.extend(scan_requirements(Path(requirements), max_bytes=max_manifest_bytes))
    if pyproject:
        deps.extend(scan_pyproject(Path(pyproject), max_bytes=max_manifest_bytes))

    for candidate, scanner in [
        ("package-lock.json", scan_package_lock),
        ("package.json", scan_package_json),
        ("go.mod", scan_go_mod),
        ("pom.xml", scan_pom),
    ]:
        path = Path(candidate)
        if path.exists():
            deps.extend(scanner(path, max_bytes=max_manifest_bytes))

    for manifest in extra_manifests:
        path = Path(manifest)
        if path.exists():
            deps.extend(
                scanner(path, max_bytes=max_manifest_bytes)
                if (scanner := _select_scanner(path)) is not None
                else []
            )

    if include_shadow_repo:
        deps.append(
            fetch_shadow_uefi_intel_dependency(
                offline=offline, timeout=shadow_timeout, repo_url=shadow_repo_url
            )
        )

    return deps


def _select_scanner(path: Path):
    mapping = {
        "requirements.txt": scan_requirements,
        "pyproject.toml": scan_pyproject,
        "package.json": scan_package_json,
        "package-lock.json": scan_package_lock,
        "go.mod": scan_go_mod,
        "pom.xml": scan_pom,
    }
    return mapping.get(path.name)


def collect_models(
    models_file: Optional[str],
    model_ids: tuple[str, ...],
    *,
    offline: bool,
    max_manifest_bytes: Optional[int],
) -> list[ModelInfo]:
    models = []
    if models_file:
        models.extend(scan_models_from_file(Path(models_file), max_bytes=max_manifest_bytes))
    if model_ids:
        models.extend(summarize_models(list(model_ids), offline=offline))
    return models


def merge_models(primary: List[ModelInfo], secondary: List[ModelInfo]) -> List[ModelInfo]:
    existing = {model.identifier for model in primary}
    for model in secondary:
        if model.identifier in existing:
            continue
        primary.append(model)
        existing.add(model.identifier)
    return primary


def parse_hash_entries(entries: tuple[str, ...], label: str) -> dict[Path, str]:
    parsed: dict[Path, str] = {}
    for entry in entries:
        if ":" not in entry:
            raise click.BadParameter(f"{label} must be in PATH:SHA256 format")
        path_text, hash_value = entry.rsplit(":", 1)
        path = Path(path_text)
        parsed[path] = hash_value.strip()
    return parsed


def parse_metadata_entries(entries: tuple[str, ...], label: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for entry in entries:
        if ":" not in entry:
            raise click.BadParameter(f"{label} must be in KEY:VALUE format")
        key, value = entry.split(":", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def build_risk_settings(config: ScanConfig, policy: object | None = None) -> RiskSettings:
    base_settings = RiskSettings()
    severity_penalties = dict(base_settings.severity_penalties)
    if config.risk_penalty_high is not None:
        severity_penalties["high"] = config.risk_penalty_high
    if config.risk_penalty_medium is not None:
        severity_penalties["medium"] = config.risk_penalty_medium
    if config.risk_penalty_low is not None:
        severity_penalties["low"] = config.risk_penalty_low

    settings = RiskSettings(
        max_score=config.risk_max_score,
        severity_penalties=severity_penalties,
        governance_penalty=config.risk_penalty_governance
        if config.risk_penalty_governance is not None
        else base_settings.governance_penalty,
        cve_penalty=config.risk_penalty_cve
        if config.risk_penalty_cve is not None
        else base_settings.cve_penalty,
    )
    if policy:
        policy_scoring_model = getattr(policy, "scoring_model", None)
        if policy_scoring_model:
            settings.scoring_model = policy_scoring_model
        policy_scoring_version = getattr(policy, "scoring_model_version", None)
        if policy_scoring_version:
            settings.scoring_model_version = policy_scoring_version
        policy_category_weights = getattr(policy, "category_weights", None) or {}
        if policy_category_weights:
            settings.category_weights = dict(policy_category_weights)
        policy_weight_scale = getattr(policy, "weight_scale", None)
        if policy_weight_scale is not None:
            settings.weight_scale = float(policy_weight_scale)
        policy_org_weights = getattr(policy, "org_weights", None) or {}
        if policy_org_weights:
            settings.org_weights = dict(policy_org_weights)
        policy_temporal = getattr(policy, "temporal_multipliers", None) or {}
        if policy_temporal:
            settings.temporal_multipliers = dict(policy_temporal)
        policy_asset = getattr(policy, "asset_criticality_multipliers", None) or {}
        if policy_asset:
            settings.asset_criticality_multipliers = dict(policy_asset)
        policy_data_sensitivity = getattr(policy, "data_sensitivity_multipliers", None) or {}
        if policy_data_sensitivity:
            settings.data_sensitivity_multipliers = dict(policy_data_sensitivity)
        policy_environment = getattr(policy, "environment_multipliers", None) or {}
        if policy_environment:
            settings.environment_multipliers = dict(policy_environment)
        policy_missing_intel = getattr(policy, "missing_intel_penalty", None)
        if policy_missing_intel is not None:
            settings.missing_intel_penalty = int(policy_missing_intel)
        policy_active_exploit = getattr(policy, "active_exploitation_penalty", None)
        if policy_active_exploit is not None:
            settings.active_exploitation_penalty = int(policy_active_exploit)
    validate_risk_settings(settings)
    return settings


def validate_risk_settings(settings: RiskSettings) -> None:
    if not (0 <= settings.max_score <= 100):
        raise ValueError("RiskSettings.max_score must be between 0 and 100.")
    if settings.weight_scale < 0:
        raise ValueError("RiskSettings.weight_scale must be non-negative.")
    if settings.missing_intel_penalty < 0:
        raise ValueError("RiskSettings.missing_intel_penalty must be non-negative.")
    if settings.active_exploitation_penalty < 0:
        raise ValueError("RiskSettings.active_exploitation_penalty must be non-negative.")
    if settings.active_exploitation_penalty > settings.max_score:
        raise ValueError("RiskSettings.active_exploitation_penalty cannot exceed max_score.")
    for severity in {"high", "medium", "low"}:
        if severity not in settings.severity_penalties:
            raise ValueError(f"Penalty for severity '{severity}' is required.")
    for severity, value in settings.severity_penalties.items():
        if value < 0:
            raise ValueError(f"Penalty for severity '{severity}' must be non-negative.")
    for key, value in settings.org_weights.items():
        if value < 0:
            raise ValueError(f"Org weight for '{key}' must be non-negative.")
    required_temporal = {"active_exploitation", "mature", "poc"}
    missing_temporal = required_temporal.difference(settings.temporal_multipliers)
    if missing_temporal:
        raise ValueError(f"Temporal multipliers missing keys: {', '.join(sorted(missing_temporal))}.")
    for key, value in settings.temporal_multipliers.items():
        if value < 1.0 or value > 5.0:
            raise ValueError(f"Temporal multiplier '{key}' must be between 1.0 and 5.0.")
    if settings.category_weights:
        total = sum(settings.category_weights.values())
        if any(weight < 0 or weight > 1 for weight in settings.category_weights.values()):
            raise ValueError("Category weights must be between 0.0 and 1.0.")
        if abs(total - 1.0) > 1e-6:
            raise ValueError("Category weights must sum to 1.0.")
    required_org_keys = {
        "asset_criticality_multipliers": {"low", "medium", "high", "critical"},
        "data_sensitivity_multipliers": {"public", "internal", "confidential", "restricted"},
        "environment_multipliers": {"dev", "test", "staging", "prod"},
    }
    for name, mapping in {
        "asset_criticality_multipliers": settings.asset_criticality_multipliers,
        "data_sensitivity_multipliers": settings.data_sensitivity_multipliers,
        "environment_multipliers": settings.environment_multipliers,
    }.items():
        missing_keys = required_org_keys[name].difference(mapping)
        if missing_keys:
            raise ValueError(f"{name} missing keys: {', '.join(sorted(missing_keys))}.")
        for key, value in mapping.items():
            if value < 1.0:
                raise ValueError(f"{name} '{key}' must be >= 1.0.")


def validate_org_context(context: OrgContext | None) -> OrgContext:
    if context is None:
        raise ValueError("Org context is required for scoring (asset criticality, data sensitivity, environment).")
    normalized = OrgContext(
        asset_criticality=context.asset_criticality.lower(),
        data_sensitivity=context.data_sensitivity.lower(),
        environment=context.environment.lower(),
    )
    if normalized.asset_criticality not in {"low", "medium", "high", "critical"}:
        raise ValueError("asset_criticality must be one of: low, medium, high, critical.")
    if normalized.data_sensitivity not in {"public", "internal", "confidential", "restricted"}:
        raise ValueError("data_sensitivity must be one of: public, internal, confidential, restricted.")
    if normalized.environment not in {"dev", "test", "staging", "prod"}:
        raise ValueError("environment must be one of: dev, test, staging, prod.")
    return normalized


def run_scan(config: ScanConfig) -> ScanResult:
    if config.license_risk_db:
        set_license_risk_db_path(Path(config.license_risk_db))
    if config.model_advisory_db:
        set_model_advisory_db_path(Path(config.model_advisory_db))
    if config.model_hash_db:
        set_model_hash_db_path(Path(config.model_hash_db))
    if config.threat_taxonomy_db:
        set_threat_taxonomy_db_path(Path(config.threat_taxonomy_db))
    if config.training_source_db:
        set_training_source_db_path(Path(config.training_source_db))

    dependencies = collect_dependencies(
        config.requirements_path,
        config.pyproject_path,
        config.manifest,
        include_shadow_repo=config.include_shadow_repo,
        shadow_timeout=config.shadow_timeout,
        shadow_repo_url=config.shadow_repo_url,
        offline=config.offline,
        max_manifest_bytes=config.max_manifest_bytes,
    )
    for sbom in config.sbom_file:
        dependencies.extend(parse_sbom(Path(sbom), max_bytes=config.max_manifest_bytes))

    models = collect_models(
        config.models_file,
        config.model_id,
        offline=config.offline,
        max_manifest_bytes=config.max_manifest_bytes,
    )

    auto_models = []
    stack_snapshot = None
    if config.discover_stack_flag:
        auto_models = discover_models(Path("."), dependencies=dependencies)
        models = merge_models(models, auto_models)
        stack_snapshot = discover_stack(
            Path("."), dependencies=dependencies, models=models, env=config.env
        )

    if auto_models and not config.models_file and not config.model_id:
        click.echo(
            f"Auto-discovered {len(auto_models)} model reference(s); pass --models-file to override or enrich.",
            err=True,
        )

    has_inputs = bool(dependencies or models)

    if config.with_cves:
        dependencies = enrich_with_osv(
            dependencies, offline=config.offline, osv_url=config.osv_url, timeout=config.osv_timeout
        )

    models = enrich_models_with_cves(models)

    policy_data = load_policy(Path(config.policy), max_bytes=config.max_manifest_bytes) if config.policy else None
    approvals = list(config.approval)

    trusted_registries = list(
        {*(policy_data.trusted_registries if policy_data else []), *config.registry_allowlist}
    )
    protected_namespaces = list(
        {*(policy_data.protected_namespaces if policy_data else []), *config.protected_namespace}
    )
    require_signatures = config.require_dependency_signatures or (
        policy_data.require_dependency_signatures if policy_data else False
    )
    apply_dependency_trust_enforcement(
        dependencies,
        TrustEnforcementConfig(
            trusted_registries=trusted_registries,
            protected_namespaces=protected_namespaces,
            require_dependency_signatures=require_signatures,
        ),
    )

    runtime_trace_data: RuntimeTrace | None = None
    if config.runtime_trace:
        runtime_trace_data = load_runtime_trace(Path(config.runtime_trace))

    env_vars = None
    if stack_snapshot:
        env_vars = [node.id for node in stack_snapshot.nodes if node.kind == "EnvVar"]

    risk_settings = build_risk_settings(config, policy_data)
    org_context = validate_org_context(config.org_context)

    policy_metadata = None
    if policy_data:
        policy_metadata = {
            "version": policy_data.policy_version,
            "scoring_model": policy_data.scoring_model,
            "scoring_model_version": policy_data.scoring_model_version,
            "change_log": policy_data.change_log,
        }
        if config.policy:
            try:
                policy_metadata["policy_hash"] = compute_output_hash(Path(config.policy).read_text())
            except Exception:
                policy_metadata["policy_hash"] = None

    intel_versions = get_intel_versions()

    input_paths = [
        Path(path)
        for path in [
            config.requirements_path,
            config.pyproject_path,
            *(list(config.manifest) if config.manifest else []),
            *(list(config.sbom_file) if config.sbom_file else []),
            config.models_file,
            config.policy,
            config.baseline_report,
            config.runtime_trace,
            config.model_advisory_db,
            config.model_hash_db,
            config.threat_taxonomy_db,
            config.license_risk_db,
            config.training_source_db,
        ]
        if path
    ]
    input_hashes = collect_input_hashes(input_paths)
    git_commit = current_git_commit(Path("."))
    provenance = {
        "git_commit": git_commit,
        "inputs": [entry.__dict__ for entry in input_hashes],
    }

    completeness = build_completeness(
        len(dependencies),
        len(models),
        runtime_trace_data,
        env_vars=env_vars,
    )

    lockfile_checksums = {
        Path(path): value for path, value in (policy_data.lockfile_checksums.items() if policy_data else {})
    }
    lockfile_checksums.update(parse_hash_entries(config.lockfile_checksum, "lockfile-checksum"))
    config_checksums = {
        Path(path): value for path, value in (policy_data.config_checksums.items() if policy_data else {})
    }
    config_checksums.update(parse_hash_entries(config.config_checksum, "config-checksum"))
    ruleset_checksums = {
        Path(path): value for path, value in (policy_data.ruleset_checksums.items() if policy_data else {})
    }
    ruleset_checksums.update(parse_hash_entries(config.ruleset_checksum, "ruleset-checksum"))
    plugin_signatures = {
        Path(path): value for path, value in (policy_data.plugin_signatures.items() if policy_data else {})
    }
    plugin_signatures.update(parse_hash_entries(config.plugin_signature, "plugin-signature"))

    integrity_findings = []
    integrity_findings.extend(
        enforce_lockfile_checksums(
            Path("."),
            lockfile_checksums,
            require_all=config.enforce_lockfile_checksums_flag
            or (policy_data.require_lockfile_checksums if policy_data else False),
        )
    )
    integrity_findings.extend(verify_expected_hashes(config_checksums, kind="config", code_prefix="CONFIG"))
    integrity_findings.extend(
        verify_expected_hashes(ruleset_checksums, kind="ruleset", code_prefix="RULESET")
    )
    integrity_findings.extend(
        verify_expected_hashes(plugin_signatures, kind="plugin", code_prefix="PLUGIN_SIGNATURE")
    )

    report = Report(
        dependencies=dependencies,
        models=models,
        generated_at=datetime.utcnow(),
        risk_settings=risk_settings,
        stack_snapshot=stack_snapshot,
        provenance=provenance,
        integrity_findings=integrity_findings,
        approvals=approvals,
        runtime_trace=runtime_trace_data,
        policy_metadata=policy_metadata,
        intel_versions=intel_versions,
    )
    scoring_model_name = (
        config.scoring_model_override
        or (policy_data.scoring_model if policy_data else None)
        or "default"
    )
    score_model = get_score_model(scoring_model_name)
    score_outcome = score_model.score(
        report,
        ScoringContext(
            org_context=org_context,
            policy_metadata=policy_metadata,
            intel_versions=intel_versions,
        ),
    )
    report.score = score_outcome.final_score
    report.score_explanation = score_outcome.explanation
    graph_context = InMemoryGraphStore()
    populate_graph_from_report(graph_context, report)
    if report.score_explanation is not None:
        report.score_explanation["relationship_context"] = {
            "kind": "graph_context_summary",
            "version": "v1",
            "node_count": len(graph_context.nodes),
            "relationship_count": len(graph_context.relationships),
            "missing_provenance_models": [
                node.properties.get("identifier", node.id)
                for node in graph_context.models_with_missing_provenance()
            ],
            "note": "Graph context is explanatory only; deterministic scoring remains authoritative.",
        }

    report.completeness = completeness
    report.executive_summary = build_executive_summary(report)
    report.framework_mapping = framework_mapping_metadata()

    if config.ai_summary:
        report.ai_summary = build_ai_summary(report)

    policy_evaluation = None
    policy_failed = False
    if policy_data:
        policy_evaluation = evaluate_policy(
            report,
            policy_data,
            graph_snapshot=stack_snapshot,
            enforce_graph=config.enforce_graph_policy and policy_data.enforce_graph_policies,
        )
        report.graph_policy_violations = policy_evaluation.graph_policy_violations
        policy_failed = not policy_evaluation.passed

    report_json = json.loads(render_report(report, "json"))

    baseline_diff = None
    if config.baseline_report:
        try:
            baseline_payload = load_json_payload(
                Path(config.baseline_report),
                max_bytes=config.max_manifest_bytes,
            )
        except ParserError as exc:
            raise RuntimeError(str(exc)) from exc
        baseline_diff = diff_reports(baseline_payload, report_json)

    score_failed = False
    if config.fail_on_score is not None and report.stack_risk_score < config.fail_on_score:
        score_failed = True

    return ScanResult(
        report=report,
        report_json=report_json,
        policy_evaluation=policy_evaluation,
        baseline_diff=baseline_diff,
        policy_failed=policy_failed,
        score_failed=score_failed,
        input_hashes=input_hashes,
        git_commit=git_commit,
        integrity_findings=integrity_findings,
        has_inputs=has_inputs,
    )
