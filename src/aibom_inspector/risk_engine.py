from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import click

from .attestation import collect_input_hashes, current_git_commit
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
from .integrity import enforce_lockfile_checksums, verify_expected_hashes
from .model_inspector import enrich_models_with_cves, scan_models_from_file, summarize_models
from .model_risk_db import (
    set_model_advisory_db_path,
    set_model_hash_db_path,
    set_threat_taxonomy_db_path,
    set_training_source_db_path,
)
from .policy import diff_reports, evaluate_policy, load_policy
from .report_enrichment import build_ai_summary, build_completeness, build_executive_summary
from .reporting import render_report
from .runtime_trace import load_runtime_trace
from .stack_discovery import discover_models, discover_stack
from .trust_enforcement import TrustEnforcementConfig, apply_dependency_trust_enforcement
from .types import ModelInfo, Report, RiskSettings, RuntimeTrace
from .types_risk import set_license_risk_db_path
from .parsers import ParserError, load_json_payload


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


def build_risk_settings(config: ScanConfig) -> RiskSettings:
    base_settings = RiskSettings()
    severity_penalties = dict(base_settings.severity_penalties)
    if config.risk_penalty_high is not None:
        severity_penalties["high"] = config.risk_penalty_high
    if config.risk_penalty_medium is not None:
        severity_penalties["medium"] = config.risk_penalty_medium
    if config.risk_penalty_low is not None:
        severity_penalties["low"] = config.risk_penalty_low

    return RiskSettings(
        max_score=config.risk_max_score,
        severity_penalties=severity_penalties,
        governance_penalty=config.risk_penalty_governance
        if config.risk_penalty_governance is not None
        else base_settings.governance_penalty,
        cve_penalty=config.risk_penalty_cve
        if config.risk_penalty_cve is not None
        else base_settings.cve_penalty,
    )


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

    risk_settings = build_risk_settings(config)

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
    )
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
