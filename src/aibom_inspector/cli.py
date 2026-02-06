from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import List, Optional
from datetime import datetime
import click

from .attestation import (
    build_attestation,
    collect_input_hashes,
    compute_output_hash,
    current_git_commit,
    write_attestation,
)
from .feedback import FeedbackEntry, append_feedback, load_feedback, summarize_feedback
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
from .model_inspector import enrich_models_with_cves, scan_models_from_file, summarize_models
from .model_risk_db import (
    set_model_advisory_db_path,
    set_model_hash_db_path,
    set_threat_taxonomy_db_path,
    set_training_source_db_path,
)
from .policy import diff_reports, evaluate_policy, load_policy, write_evidence_pack, write_github_check
from .policy_graph import evaluate_graph_policies
from .pickle_inspector import PickleFileTooLargeError, inspect_pickle_files
from .report_enrichment import build_completeness, build_executive_summary
from .reporting import render_report, write_report
from .runtime_trace import load_runtime_trace, trace_python
from .audit_log import append_audit_log, build_audit_entry, verify_audit_log
from .evidence_export import write_evidence_export
from .integrity import compute_file_sha256, enforce_lockfile_checksums, verify_expected_hashes
from .ip_protection import protect_ip
from .control_plane import build_control_plane_bundle, write_control_plane_bundle
from .report_loader import load_report_payload
from .trust_root import (
    create_trust_root,
    load_trust_root,
    sign_payload,
    trust_root_fingerprint,
    verify_payload,
    verify_trust_root,
    write_trust_root,
)
from .stack_discovery import discover_models, discover_stack
from .tensor_fuzz import inspect_weight_files
from .trust_enforcement import TrustEnforcementConfig, apply_dependency_trust_enforcement
from .types import ModelInfo, Report, RiskSettings, RuntimeTrace
from .types_risk import set_license_risk_db_path
from .framework_mapping import framework_mapping_metadata


def _collect_dependencies(
    requirements: Optional[str],
    pyproject: Optional[str],
    extra_manifests: tuple[str, ...],
    include_shadow_repo: bool,
    shadow_timeout: Optional[float],
    shadow_repo_url: Optional[str],
    offline: bool,
):
    deps = []
    if requirements:
        deps.extend(scan_requirements(Path(requirements)))
    if pyproject:
        deps.extend(scan_pyproject(Path(pyproject)))

    for candidate, scanner in [
        ("package-lock.json", scan_package_lock),
        ("package.json", scan_package_json),
        ("go.mod", scan_go_mod),
        ("pom.xml", scan_pom),
    ]:
        path = Path(candidate)
        if path.exists():
            deps.extend(scanner(path))

    for manifest in extra_manifests:
        path = Path(manifest)
        if path.exists():
            deps.extend(scanner(path) if (scanner := _select_scanner(path)) else [])

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


def _collect_models(models_file: Optional[str], model_ids: tuple[str, ...], offline: bool):
    models = []
    if models_file:
        models.extend(scan_models_from_file(Path(models_file)))
    if model_ids:
        models.extend(summarize_models(list(model_ids), offline=offline))
    return models


def _merge_models(primary: List[ModelInfo], secondary: List[ModelInfo]) -> List[ModelInfo]:
    existing = {model.identifier for model in primary}
    for model in secondary:
        if model.identifier in existing:
            continue
        primary.append(model)
        existing.add(model.identifier)
    return primary


def _parse_hash_entries(entries: tuple[str, ...], label: str) -> dict[Path, str]:
    parsed: dict[Path, str] = {}
    for entry in entries:
        if ":" not in entry:
            raise click.BadParameter(f"{label} must be in PATH:SHA256 format")
        path_text, hash_value = entry.rsplit(":", 1)
        path = Path(path_text)
        parsed[path] = hash_value.strip()
    return parsed


def _parse_metadata_entries(entries: tuple[str, ...], label: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for entry in entries:
        if ":" not in entry:
            raise click.BadParameter(f"{label} must be in KEY:VALUE format")
        key, value = entry.split(":", 1)
        parsed[key.strip()] = value.strip()
    return parsed


@click.group()
def main() -> None:
    """AI-BOM Inspector CLI."""


@main.command()
@click.option(
    "--requirements",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Path to requirements file (auto-detected if omitted).",
)
@click.option(
    "--pyproject",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Path to pyproject file (auto-detected if omitted).",
)
@click.option(
    "--models-file",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="JSON file describing models to inspect.",
)
@click.option(
    "--model-id",
    multiple=True,
    help="HuggingFace model identifiers to include when no file is available.",
)
@click.option(
    "--manifest",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Additional manifest files (package-lock.json, go.mod, pom.xml, etc.).",
)
@click.option(
    "--sbom-file",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Existing CycloneDX/SPDX SBOMs to include in the scan context.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "markdown", "md", "html", "sarif", "cyclonedx", "spdx"], case_sensitive=False),
    default="markdown",
    show_default=True,
    help="Output format for the report.",
)
@click.option(
    "--output",
    type=click.Path(dir_okay=False, writable=True, path_type=str),
    help="Write the report to a file instead of stdout.",
)
@click.option(
    "--markdown-output",
    type=click.Path(dir_okay=False, writable=True, path_type=str),
    help="Optionally emit a Markdown copy of the report alongside the primary format.",
)
@click.option(
    "--sarif-output",
    type=click.Path(dir_okay=False, writable=True, path_type=str),
    help="Optionally emit a SARIF security report alongside the primary format.",
)
@click.option(
    "--sbom-output",
    type=click.Path(dir_okay=False, writable=True, path_type=str),
    help="Optional destination path for CycloneDX/SPDX output (if format is SBOM).",
)
@click.option(
    "--ai-summary",
    is_flag=True,
    help="Include a placeholder AI-generated summary (offline stub).",
)
@click.option(
    "--fail-on-score",
    type=int,
    help="Exit non-zero when the stack risk score falls below the threshold (0-100, higher = healthier).",
)
@click.option(
    "--with-cves",
    is_flag=True,
    help="Enrich dependencies with OSV vulnerability lookups (best-effort).",
)
@click.option(
    "--risk-max-score",
    type=int,
    default=100,
    show_default=True,
    help="Upper bound for the AI stack risk score (0-100 by default).",
)
@click.option(
    "--risk-penalty-high",
    type=int,
    help="Custom penalty for high-severity findings when computing the stack risk score.",
)
@click.option(
    "--risk-penalty-medium",
    type=int,
    help="Custom penalty for medium-severity findings when computing the stack risk score.",
)
@click.option(
    "--risk-penalty-low",
    type=int,
    help="Custom penalty for low-severity findings when computing the stack risk score.",
)
@click.option(
    "--risk-penalty-governance",
    type=int,
    help="Penalty applied per high-risk governance flag (missing pins, unverified sources).",
)
@click.option(
    "--risk-penalty-cve",
    type=int,
    help="Penalty applied per CVE or advisory hit during CVE feed cross-checks.",
)
@click.option(
    "--enable-shadow-uefi-intel/--disable-shadow-uefi-intel",
    default=False,
    show_default=True,
    help="Opt-in: fetch Shadow-UEFI-Intel repository metadata as dependency context.",
)
@click.option(
    "--offline/--online",
    default=True,
    show_default=True,
    help=(
        "Run without remote lookups by default; pass --online to allow OSV, "
        "HuggingFace, and explicitly enabled Shadow-UEFI-Intel network calls."
    ),
)
@click.option(
    "--osv-url",
    type=str,
    help="Override the OSV endpoint (defaults to OSV_API_URL env var or the public API).",
)
@click.option(
    "--osv-timeout",
    type=float,
    help="HTTP timeout (seconds) for OSV lookups; defaults to OSV_API_TIMEOUT or 8s.",
)
@click.option(
    "--model-advisory-db",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Path to a local model advisory database (JSON feed).",
)
@click.option(
    "--model-hash-db",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Path to a local model hash reputation database (JSON feed).",
)
@click.option(
    "--threat-taxonomy-db",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Path to a local AI threat taxonomy mapping (JSON).",
)
@click.option(
    "--license-risk-db",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Path to a license risk override database (JSON).",
)
@click.option(
    "--training-source-db",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Path to a training source fingerprint database (JSON).",
)
@click.option(
    "--shadow-uefi-timeout",
    type=float,
    help="HTTP timeout (seconds) for fetching Shadow-UEFI-Intel metadata; defaults to SHADOW_UEFI_INTEL_TIMEOUT or 8s.",
)
@click.option(
    "--shadow-uefi-repo",
    type=str,
    help=(
        "Override the repository URL used when fetching Shadow-UEFI-Intel context. "
        "Defaults to SHADOW_UEFI_INTEL_REPO or the upstream repository."
    ),
)
@click.option(
    "--require-input",
    is_flag=True,
    help="Fail the scan if no dependencies or models are discovered.",
)
@click.option(
    "--approval",
    multiple=True,
    help="Approval tags for policy compliance (repeatable).",
)
@click.option(
    "--audit-log",
    type=click.Path(dir_okay=False, writable=True, path_type=str),
    help="Append a tamper-evident audit log entry for the scan.",
)
@click.option(
    "--audit-actor",
    type=str,
    help="Optional actor identifier for audit logging.",
)
@click.option(
    "--registry-allowlist",
    multiple=True,
    help="Allowed dependency registries (repeatable, e.g., pypi, npm, internal.host).",
)
@click.option(
    "--protected-namespace",
    multiple=True,
    help="Namespace prefixes reserved for internal packages to detect dependency confusion.",
)
@click.option(
    "--require-dependency-signatures",
    is_flag=True,
    help="Require signature metadata on dependencies when available.",
)
@click.option(
    "--lockfile-checksum",
    multiple=True,
    help="Expected lockfile checksum in PATH:SHA256 format (repeatable).",
)
@click.option(
    "--enforce-lockfile-checksums",
    "enforce_lockfile_checksums_flag",
    is_flag=True,
    help="Require checksums for all detected lockfiles.",
)
@click.option(
    "--config-checksum",
    multiple=True,
    help="Expected config checksum in PATH:SHA256 format (repeatable).",
)
@click.option(
    "--ruleset-checksum",
    multiple=True,
    help="Expected ruleset checksum in PATH:SHA256 format (repeatable).",
)
@click.option(
    "--plugin-signature",
    multiple=True,
    help="Expected plugin signature in PATH:SHA256 format (repeatable).",
)
@click.option(
    "--discover-stack/--skip-stack-discovery",
    "discover_stack_flag",
    default=True,
    show_default=True,
    help="Auto-detect agents, tools, providers, MCP configs, and env vars in the working tree.",
)
@click.option(
    "--enforce-graph-policy/--no-enforce-graph-policy",
    default=True,
    show_default=True,
    help="Enforce default graph-based guardrails (unpinned models in prod, unsafe tools, MCP write scopes).",
)
@click.option(
    "--env",
    type=click.Choice(["dev", "staging", "prod", "test"], case_sensitive=False),
    default="dev",
    show_default=True,
    help="Environment context used for stack discovery and graph policy evaluation.",
)
@click.option(
    "--policy",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Path to a policy-as-code YAML file for CI gating.",
)
@click.option(
    "--github-check-output",
    type=click.Path(dir_okay=False, writable=True, path_type=str),
    help="Write a GitHub Check-style JSON summary for PR gating.",
)
@click.option(
    "--evidence-pack",
    type=click.Path(file_okay=False, path_type=str),
    help="Directory to write an audit-friendly evidence bundle (policy decisions, signed report).",
)
@click.option(
    "--evidence-prev-hash",
    type=str,
    help="Previous evidence bundle hash to chain evidence manifests.",
)
@click.option(
    "--sign-evidence",
    is_flag=True,
    help="Sign evidence manifest and report artifacts using the trust root.",
)
@click.option(
    "--sign-report",
    is_flag=True,
    help="Emit a SHA256 signature alongside the rendered report for tamper evidence.",
)
@click.option(
    "--trust-root",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Path to a trust root JSON for signing/verifying attestations.",
)
@click.option(
    "--attestation-output",
    type=click.Path(dir_okay=False, writable=True, path_type=str),
    help="Write a machine-readable provenance attestation JSON file.",
)
@click.option(
    "--runtime-trace",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Optional runtime trace JSON captured via `aibom trace`.",
)
@click.option(
    "--baseline-report",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Previous JSON report to diff against for change detection.",
)
@click.option(
    "--control-plane-output",
    type=click.Path(dir_okay=False, writable=True, path_type=str),
    help="Write a Control Plane bundle JSON for enterprise ingestion.",
)
@click.option(
    "--control-plane-org",
    type=str,
    help="Organization ID for the Control Plane bundle.",
)
@click.option(
    "--control-plane-project",
    type=str,
    help="Project ID for the Control Plane bundle.",
)
@click.option(
    "--control-plane-environment",
    type=str,
    help="Environment name (dev/staging/prod) for the Control Plane bundle.",
)
@click.option(
    "--control-plane-asset-type",
    type=click.Choice(["model", "dataset", "pipeline"], case_sensitive=False),
    help="Asset type for the Control Plane bundle.",
)
@click.option(
    "--control-plane-asset-fingerprint",
    type=str,
    help="Asset fingerprint or immutable identifier for the Control Plane bundle.",
)
@click.option(
    "--control-plane-asset-id",
    type=str,
    help="Optional asset ID if the asset is already registered.",
)
@click.option(
    "--control-plane-prev-hash",
    type=str,
    help="Previous bundle hash to chain evidence records.",
)
@click.option(
    "--control-plane-metadata",
    "control_plane_metadata",
    multiple=True,
    help="Additional metadata for the Control Plane bundle in KEY:VALUE format (repeatable).",
)
def scan(
    requirements: Optional[str],
    pyproject: Optional[str],
    models_file: Optional[str],
    model_id: tuple[str, ...],
    manifest: tuple[str, ...],
    sbom_file: tuple[str, ...],
    fmt: str,
    output: Optional[str],
    markdown_output: Optional[str],
    sarif_output: Optional[str],
    sbom_output: Optional[str],
    ai_summary: bool,
    fail_on_score: Optional[int],
    with_cves: bool,
    risk_max_score: int,
    risk_penalty_high: Optional[int],
    risk_penalty_medium: Optional[int],
    risk_penalty_low: Optional[int],
    risk_penalty_governance: Optional[int],
    risk_penalty_cve: Optional[int],
    enable_shadow_uefi_intel: bool,
    offline: bool,
    osv_url: Optional[str],
    osv_timeout: Optional[float],
    model_advisory_db: Optional[str],
    model_hash_db: Optional[str],
    threat_taxonomy_db: Optional[str],
    license_risk_db: Optional[str],
    training_source_db: Optional[str],
    shadow_uefi_timeout: Optional[float],
    shadow_uefi_repo: Optional[str],
    require_input: bool,
    approval: tuple[str, ...],
    audit_log: Optional[str],
    audit_actor: Optional[str],
    registry_allowlist: tuple[str, ...],
    protected_namespace: tuple[str, ...],
    require_dependency_signatures: bool,
    lockfile_checksum: tuple[str, ...],
    enforce_lockfile_checksums_flag: bool,
    config_checksum: tuple[str, ...],
    ruleset_checksum: tuple[str, ...],
    plugin_signature: tuple[str, ...],
    discover_stack_flag: bool,
    enforce_graph_policy: bool,
    env: str,
    policy: Optional[str],
    github_check_output: Optional[str],
    evidence_pack: Optional[str],
    evidence_prev_hash: Optional[str],
    sign_evidence: bool,
    sign_report: bool,
    trust_root: Optional[str],
    attestation_output: Optional[str],
    runtime_trace: Optional[str],
    baseline_report: Optional[str],
    control_plane_output: Optional[str],
    control_plane_org: Optional[str],
    control_plane_project: Optional[str],
    control_plane_environment: Optional[str],
    control_plane_asset_type: Optional[str],
    control_plane_asset_fingerprint: Optional[str],
    control_plane_asset_id: Optional[str],
    control_plane_prev_hash: Optional[str],
    control_plane_metadata: tuple[str, ...],
) -> None:
    """Scan dependencies, models, and produce a report."""
    requirements_path = requirements or (
        str(Path("requirements.txt")) if Path("requirements.txt").exists() else None
    )
    pyproject_path = pyproject or (str(Path("pyproject.toml")) if Path("pyproject.toml").exists() else None)

    if license_risk_db:
        set_license_risk_db_path(Path(license_risk_db))
    if model_advisory_db:
        set_model_advisory_db_path(Path(model_advisory_db))
    if model_hash_db:
        set_model_hash_db_path(Path(model_hash_db))
    if threat_taxonomy_db:
        set_threat_taxonomy_db_path(Path(threat_taxonomy_db))
    if training_source_db:
        set_training_source_db_path(Path(training_source_db))

    dependencies = _collect_dependencies(
        requirements_path,
        pyproject_path,
        manifest,
        include_shadow_repo=enable_shadow_uefi_intel,
        shadow_timeout=shadow_uefi_timeout,
        shadow_repo_url=shadow_uefi_repo,
        offline=offline,
    )
    for sbom in sbom_file:
        dependencies.extend(parse_sbom(Path(sbom)))

    models = _collect_models(models_file, model_id, offline)

    auto_models = []
    if discover_stack_flag:
        auto_models = discover_models(Path("."), dependencies=dependencies)
        models = _merge_models(models, auto_models)

    stack_snapshot = None
    if discover_stack_flag:
        stack_snapshot = discover_stack(
            Path("."), dependencies=dependencies, models=models, env=env
        )
        if auto_models and not models_file and not model_id:
            click.echo(
                f"Auto-discovered {len(auto_models)} model reference(s); pass --models-file to override or enrich.",
                err=True,
            )

    if not dependencies and not models:
        click.echo("No dependencies or models detected; nothing to scan.", err=True)
        if require_input:
            raise SystemExit(1)

    if with_cves:
        dependencies = enrich_with_osv(dependencies, offline=offline, osv_url=osv_url, timeout=osv_timeout)

    models = enrich_models_with_cves(models)

    policy_data = load_policy(Path(policy)) if policy else None
    approvals = list(approval)

    trusted_registries = list(
        {*(policy_data.trusted_registries if policy_data else []), *registry_allowlist}
    )
    protected_namespaces = list(
        {*(policy_data.protected_namespaces if policy_data else []), *protected_namespace}
    )
    require_signatures = require_dependency_signatures or (
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
    if runtime_trace:
        runtime_trace_data = load_runtime_trace(Path(runtime_trace))

    env_vars = None
    if stack_snapshot:
        env_vars = [node.id for node in stack_snapshot.nodes if node.kind == "EnvVar"]

    base_settings = RiskSettings()
    severity_penalties = dict(base_settings.severity_penalties)
    if risk_penalty_high is not None:
        severity_penalties["high"] = risk_penalty_high
    if risk_penalty_medium is not None:
        severity_penalties["medium"] = risk_penalty_medium
    if risk_penalty_low is not None:
        severity_penalties["low"] = risk_penalty_low

    risk_settings = RiskSettings(
        max_score=risk_max_score,
        severity_penalties=severity_penalties,
        governance_penalty=risk_penalty_governance
        if risk_penalty_governance is not None
        else base_settings.governance_penalty,
        cve_penalty=risk_penalty_cve if risk_penalty_cve is not None else base_settings.cve_penalty,
    )

    summary = None
    if ai_summary:
        summary = "AI summarization is disabled by default. Provide an LLM backend to enable rich summaries."

    input_paths = [
        Path(path)
        for path in [
            requirements_path,
            pyproject_path,
            *(list(manifest) if manifest else []),
            *(list(sbom_file) if sbom_file else []),
            models_file,
            policy,
            baseline_report,
            runtime_trace,
            model_advisory_db,
            model_hash_db,
            threat_taxonomy_db,
            license_risk_db,
            training_source_db,
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
    lockfile_checksums.update(_parse_hash_entries(lockfile_checksum, "lockfile-checksum"))
    config_checksums = {
        Path(path): value for path, value in (policy_data.config_checksums.items() if policy_data else {})
    }
    config_checksums.update(_parse_hash_entries(config_checksum, "config-checksum"))
    ruleset_checksums = {
        Path(path): value for path, value in (policy_data.ruleset_checksums.items() if policy_data else {})
    }
    ruleset_checksums.update(_parse_hash_entries(ruleset_checksum, "ruleset-checksum"))
    plugin_signatures = {
        Path(path): value for path, value in (policy_data.plugin_signatures.items() if policy_data else {})
    }
    plugin_signatures.update(_parse_hash_entries(plugin_signature, "plugin-signature"))

    integrity_findings = []
    integrity_findings.extend(
        enforce_lockfile_checksums(
            Path("."),
            lockfile_checksums,
            require_all=enforce_lockfile_checksums_flag
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
        ai_summary=summary,
        risk_settings=risk_settings,
        stack_snapshot=stack_snapshot,
        provenance=provenance,
        integrity_findings=integrity_findings,
        approvals=approvals,
        runtime_trace=runtime_trace_data,
        completeness=completeness,
    )
    report.executive_summary = build_executive_summary(report)
    report.framework_mapping = framework_mapping_metadata()

    rendered = render_report(report, fmt)
    destination = Path(output) if output else None
    report_path: Path | None = destination
    if fmt in {"cyclonedx", "spdx"} and sbom_output:
        report_path = Path(sbom_output)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(rendered)
    else:
        rendered = write_report(report, fmt, destination)
        report_path = destination
        if not destination:
            report_path = Path(f"aibom-report.{fmt}")
            click.echo(rendered)

    markdown_payload = None
    if markdown_output:
        markdown_payload = write_report(report, "markdown", Path(markdown_output))

    sarif_payload = None
    if sarif_output:
        sarif_payload = write_report(report, "sarif", Path(sarif_output))

    policy_evaluation = None
    report_json = json.loads(render_report(report, "json"))
    baseline_diff = None
    if baseline_report:
        try:
            base_data = json.loads(Path(baseline_report).read_text())
            baseline_diff = diff_reports(base_data, report_json)
        except Exception as exc:  # pragma: no cover - I/O heavy
            click.echo(f"Unable to diff with baseline report: {exc}", err=True)

    graph_policy_requested = enforce_graph_policy
    policy_failed = False
    if policy_data:
        graph_policy_requested = graph_policy_requested or policy_data.enforce_graph_policies
        policy_evaluation = evaluate_policy(
            report,
            policy_data,
            graph_snapshot=stack_snapshot,
            enforce_graph=graph_policy_requested,
        )
        report.graph_policy_violations = policy_evaluation.graph_policy_violations
        if github_check_output:
            write_github_check(Path(github_check_output), policy_evaluation, report)
        if not policy_evaluation.passed:
            policy_failed = True
    elif graph_policy_requested and stack_snapshot:
        violations = evaluate_graph_policies(stack_snapshot)
        report.graph_policy_violations = violations
        if any(v.severity.lower() == "error" for v in violations):
            policy_failed = True

    score_failed = False
    if fail_on_score is not None:
        if report.stack_risk_score < fail_on_score:
            score_failed = True

    signature_text = None
    if sign_report:
        digest = hashlib.sha256(rendered.encode()).hexdigest()
        sig_path = (report_path or Path(f"aibom-report.{fmt}")).with_suffix(
            (report_path or Path(f"aibom-report.{fmt}")).suffix + ".sha256"
        )
        sig_path.parent.mkdir(parents=True, exist_ok=True)
        sig_path.write_text(digest)
        signature_text = digest

    output_hashes: dict[str, str] = {}
    report_hash = compute_output_hash(rendered)
    output_hashes[str(report_path or Path(f"aibom-report.{fmt}"))] = report_hash
    if markdown_output and markdown_payload is not None:
        output_hashes[str(Path(markdown_output))] = compute_output_hash(markdown_payload)
    if sarif_output and sarif_payload is not None:
        output_hashes[str(Path(sarif_output))] = compute_output_hash(sarif_payload)

    if attestation_output or evidence_pack:
        attestation_path = Path(attestation_output) if attestation_output else Path(evidence_pack) / "attestation.json"
        attestation_payload = build_attestation(
            inputs=input_hashes,
            report_hash=report_hash,
            report_path=report_path or Path(f"aibom-report.{fmt}"),
            report_format=fmt,
            output_hashes=output_hashes,
            git_commit=git_commit,
            signature=signature_text,
            metadata={"runtime_trace": bool(runtime_trace_data)},
        )
        if trust_root:
            root = load_trust_root(Path(trust_root))
            signature = sign_payload(attestation_payload, root)
            attestation_payload["attestation_signature"] = {
                "key_id": root.key_id,
                "algorithm": root.algorithm,
                "value": signature,
                "fingerprint": trust_root_fingerprint(root),
            }
        write_attestation(attestation_path, attestation_payload)
    else:
        attestation_path = None

    if audit_log:
        entry = build_audit_entry(
            action="scan",
            actor=audit_actor,
            report_path=report_path or Path(f"aibom-report.{fmt}"),
            report_sha256=report_hash,
            attestation_path=Path(attestation_output) if attestation_output else None,
            policy_path=Path(policy) if policy else None,
            approvals=approvals,
            metadata={"format": fmt, "offline": offline},
        )
        append_audit_log(Path(audit_log), entry)

    if evidence_pack:
        evidence_trust_root = load_trust_root(Path(trust_root)) if sign_evidence and trust_root else None
        write_evidence_pack(
            Path(evidence_pack),
            rendered,
            report_path or Path(f"aibom-report.{fmt}"),
            policy_evaluation,
            Path(policy) if policy else None,
            baseline_diff,
            signature_text,
            previous_hash=evidence_prev_hash,
            trust_root=evidence_trust_root,
        )

    if control_plane_output:
        missing_fields = []
        if not control_plane_org:
            missing_fields.append("--control-plane-org")
        if not control_plane_project:
            missing_fields.append("--control-plane-project")
        if not control_plane_environment:
            missing_fields.append("--control-plane-environment")
        if not control_plane_asset_type:
            missing_fields.append("--control-plane-asset-type")
        if not control_plane_asset_fingerprint:
            missing_fields.append("--control-plane-asset-fingerprint")
        if missing_fields:
            raise click.BadParameter(
                f"Missing required Control Plane fields: {', '.join(missing_fields)}"
            )
        bundle = build_control_plane_bundle(
            report=report_json,
            report_hash=compute_output_hash(json.dumps(report_json, sort_keys=True)),
            org_id=control_plane_org,
            project_id=control_plane_project,
            environment=control_plane_environment,
            asset_type=control_plane_asset_type or "",
            asset_fingerprint=control_plane_asset_fingerprint,
            asset_id=control_plane_asset_id,
            policy_evaluation=policy_evaluation,
            metadata=_parse_metadata_entries(control_plane_metadata, "control-plane-metadata"),
            signature=signature_text,
            attestation_path=attestation_path,
            previous_hash=control_plane_prev_hash,
        )
        write_control_plane_bundle(Path(control_plane_output), bundle)

    if policy_failed or score_failed:
        raise SystemExit(1)


@main.command()
@click.argument("script", type=click.Path(exists=True, dir_okay=False, path_type=str))
@click.argument("args", nargs=-1)
@click.option(
    "--output",
    type=click.Path(dir_okay=False, writable=True, path_type=str),
    default="aibom-runtime-trace.json",
    show_default=True,
    help="Path to write the runtime trace JSON.",
)
def trace(script: str, args: tuple[str, ...], output: str) -> None:
    """Run a Python script with import/model-load tracing enabled."""

    result = trace_python(Path(script), args)
    payload = asdict(result)
    payload["captured_at"] = result.captured_at.isoformat()
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(json.dumps(payload, indent=2))
    click.echo(f"Wrote runtime trace to {output}")


@main.command("trust-root")
@click.option(
    "--output",
    type=click.Path(dir_okay=False, writable=True, path_type=str),
    default="aibom-trust-root.json",
    show_default=True,
    help="Write a new trust root JSON file.",
)
def trust_root(output: str) -> None:
    """Generate a new trust root for signing attestations."""

    root = create_trust_root()
    write_trust_root(Path(output), root)
    click.echo(f"Wrote trust root to {output}")
    click.echo(f"Trust root fingerprint: {trust_root_fingerprint(root)}")


@main.command("verify-attestation")
@click.option(
    "--attestation",
    "attestation_path",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    required=True,
    help="Path to attestation JSON to verify.",
)
@click.option(
    "--trust-root",
    "trust_root_path",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    required=True,
    help="Trust root JSON used for verification.",
)
def verify_attestation(attestation_path: str, trust_root_path: str) -> None:
    """Verify an attestation signature against a trust root."""

    payload = json.loads(Path(attestation_path).read_text())
    signature = payload.pop("attestation_signature", None) or payload.pop("signature", None)
    if not signature or not signature.get("value"):
        click.echo("Attestation missing signature.", err=True)
        raise SystemExit(1)
    root = load_trust_root(Path(trust_root_path))
    if signature.get("key_id") != root.key_id:
        click.echo("Signature key_id does not match trust root.", err=True)
        raise SystemExit(1)
    valid = verify_payload(payload, signature["value"], root)
    if not valid:
        click.echo("Attestation signature invalid.", err=True)
        raise SystemExit(1)
    click.echo("Attestation signature verified.")


@main.command("verify-trust-root")
@click.option(
    "--trust-root",
    "trust_root_path",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    required=True,
    help="Trust root JSON to verify.",
)
def verify_trust_root_cmd(trust_root_path: str) -> None:
    """Verify the trust root signature for auditability."""

    root = load_trust_root(Path(trust_root_path))
    if not verify_trust_root(root):
        click.echo("Trust root signature invalid or missing.", err=True)
        raise SystemExit(1)
    click.echo("Trust root signature verified.")


@main.command("verify-report")
@click.option(
    "--report",
    "report_path",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    required=True,
    help="Report file to verify.",
)
@click.option(
    "--sha256",
    "sha256_path",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Path to the .sha256 file produced by --sign-report.",
)
@click.option(
    "--attestation",
    "attestation_path",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Attestation JSON containing the report hash.",
)
def verify_report(report_path: str, sha256_path: Optional[str], attestation_path: Optional[str]) -> None:
    """Verify report hashes against a .sha256 file or attestation payload."""

    if not sha256_path and not attestation_path:
        click.echo("Provide --sha256 and/or --attestation to verify report integrity.", err=True)
        raise SystemExit(1)

    report_hash = compute_file_sha256(Path(report_path))
    failures = []

    if sha256_path:
        expected = Path(sha256_path).read_text().strip().split()[0]
        if report_hash != expected:
            failures.append("SHA256 file hash mismatch.")

    if attestation_path:
        payload = json.loads(Path(attestation_path).read_text())
        expected = (payload.get("report") or {}).get("sha256")
        if not expected:
            failures.append("Attestation missing report SHA256.")
        elif report_hash != expected:
            failures.append("Attestation report hash mismatch.")

    if failures:
        for failure in failures:
            click.echo(failure, err=True)
        raise SystemExit(1)

    click.echo("Report hash verified.")


@main.command("simulate-policy")
@click.option(
    "--report",
    "report_path",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    required=True,
    help="JSON report file to simulate policy evaluation against.",
)
@click.option(
    "--policy",
    "policy_path",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    required=True,
    help="Policy YAML file to simulate.",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, writable=True, path_type=str),
    help="Optional output path for the simulation result JSON.",
)
@click.option(
    "--enforce-graph-policy/--no-enforce-graph-policy",
    default=False,
    show_default=True,
    help="Evaluate graph policy guardrails when graph data is available.",
)
def simulate_policy_cmd(
    report_path: str,
    policy_path: str,
    output_path: Optional[str],
    enforce_graph_policy: bool,
) -> None:
    """Simulate policy evaluation without blocking a pipeline."""

    payload = json.loads(Path(report_path).read_text())
    report = load_report_payload(payload)
    policy = load_policy(Path(policy_path))
    evaluation = evaluate_policy(
        report,
        policy,
        graph_snapshot=report.stack_snapshot,
        enforce_graph=policy.enforce_graph_policies or enforce_graph_policy,
    )

    result = {
        "would_block": not evaluation.passed,
        "failures": evaluation.failures,
        "used_exceptions": [entry.as_dict() for entry in evaluation.used_exceptions],
        "expired_exceptions": [entry.as_dict() for entry in evaluation.expired_exceptions],
        "graph_policy_violations": [asdict(v) for v in evaluation.graph_policy_violations],
    }

    output_json = json.dumps(result, indent=2)
    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(output_json)
        click.echo(f"Wrote policy simulation to {output_path}")
    else:
        click.echo(output_json)


@main.command("verify-audit-log")
@click.option(
    "--audit-log",
    "audit_log_path",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    required=True,
    help="Audit log JSONL file to verify.",
)
def verify_audit_log_cmd(audit_log_path: str) -> None:
    """Verify the tamper-evident audit log hash chain."""

    errors = verify_audit_log(Path(audit_log_path))
    if errors:
        for error in errors:
            click.echo(error, err=True)
        raise SystemExit(1)
    click.echo("Audit log verified.")


@main.command("export-evidence")
@click.option(
    "--report",
    "report_path",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    required=True,
    help="JSON report file to export evidence from.",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, writable=True, path_type=str),
    required=True,
    help="Output path for the evidence export JSON.",
)
def export_evidence(report_path: str, output_path: str) -> None:
    """Export compliance evidence with framework mappings."""

    write_evidence_export(Path(report_path), Path(output_path))
    click.echo(f"Wrote evidence export to {output_path}")


@main.command("ip-protect")
@click.option(
    "--obfuscate",
    "obfuscate_paths",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Python files to obfuscate (repeatable).",
)
@click.option(
    "--strip-symbols",
    "strip_paths",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Binary files to strip symbols from (repeatable).",
)
@click.option(
    "--output-dir",
    type=click.Path(file_okay=False, path_type=str),
    default="ip-protection",
    show_default=True,
    help="Directory for obfuscated/stripped outputs.",
)
@click.option(
    "--strip-tool",
    type=str,
    help="Override strip tool path (defaults to `strip` in PATH).",
)
def ip_protect(
    obfuscate_paths: tuple[str, ...],
    strip_paths: tuple[str, ...],
    output_dir: str,
    strip_tool: Optional[str],
) -> None:
    """Apply selective obfuscation and symbol stripping for IP protection."""

    if not obfuscate_paths and not strip_paths:
        click.echo("No IP protection targets supplied.", err=True)
        raise SystemExit(1)
    results = protect_ip(
        obfuscate_paths=[Path(path) for path in obfuscate_paths],
        strip_paths=[Path(path) for path in strip_paths],
        output_dir=Path(output_dir),
        strip_tool=strip_tool,
    )
    failures = [result for result in results if result.status != "ok"]
    for result in results:
        status = "ok" if result.status == "ok" else "error"
        message = f" ({result.message})" if result.message else ""
        click.echo(f"[{status}] {result.action}: {result.path} -> {result.output_path}{message}")
    if failures:
        raise SystemExit(1)


@main.command()
@click.option("--summary", required=True, help="Short summary of the feedback.")
@click.option(
    "--category",
    required=True,
    type=click.Choice(["bug", "feature", "ux", "governance", "integration", "other"]),
    help="Feedback category.",
)
@click.option(
    "--priority",
    required=True,
    type=click.Choice(["low", "medium", "high", "urgent"]),
    help="Priority level.",
)
@click.option("--finding-code", help="Related issue or finding code.")
@click.option("--organization", help="Customer organization.")
@click.option("--contact", help="Contact email or handle.")
@click.option("--workflow-stage", help="Workflow stage (e.g., onboarding, audit, CI gate).")
@click.option("--notes", help="Additional notes.")
@click.option(
    "--output",
    type=click.Path(dir_okay=False, writable=True, path_type=str),
    default="aibom-feedback.json",
    show_default=True,
    help="Feedback JSON store.",
)
def feedback(
    summary: str,
    category: str,
    priority: str,
    finding_code: Optional[str],
    organization: Optional[str],
    contact: Optional[str],
    workflow_stage: Optional[str],
    notes: Optional[str],
    output: str,
) -> None:
    """Capture customer feedback into a structured JSON log."""

    entry = FeedbackEntry(
        summary=summary,
        category=category,
        priority=priority,
        finding_code=finding_code,
        organization=organization,
        contact=contact,
        workflow_stage=workflow_stage,
        notes=notes,
    )
    append_feedback(Path(output), entry)
    click.echo(f"Saved feedback to {output}")


@main.command("feedback-metrics")
@click.option(
    "--input",
    "input_path",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    default="aibom-feedback.json",
    show_default=True,
    help="Feedback JSON store to summarize.",
)
@click.option(
    "--output",
    type=click.Path(dir_okay=False, writable=True, path_type=str),
    help="Optional path to write summary JSON.",
)
def feedback_metrics(input_path: str, output: Optional[str]) -> None:
    """Summarize feedback for dashboards and workflow adoption metrics."""

    entries = load_feedback(Path(input_path))
    summary = summarize_feedback(entries)
    payload = json.dumps(summary, indent=2)
    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(payload)
        click.echo(f"Wrote feedback metrics to {output}")
    else:
        click.echo(payload)


@main.command()
@click.argument("weights", nargs=-1, type=click.Path(exists=True, dir_okay=False, path_type=str))
@click.option(
    "--sample-limit",
    type=int,
    default=200_000,
    show_default=True,
    help="Maximum number of tensor values to sample when inspecting each file.",
)
@click.option("--json", "json_output", is_flag=True, help="Emit JSON instead of human text.")
@click.option(
    "--fail-on-suspect",
    is_flag=True,
    help="Exit non-zero if any tensor appears poisoned or carries steganography.",
)
def weights(weights: tuple[str, ...], sample_limit: int, json_output: bool, fail_on_suspect: bool) -> None:
    """Inspect safetensors weight files for poisoned neurons or LSB steganography."""

    if not weights:
        click.echo("No safetensors files supplied; nothing to inspect.", err=True)
        raise SystemExit(1)

    results = inspect_weight_files(weights, sample_limit=sample_limit)

    if json_output:
        payload = [result.as_dict() for result in results]
        click.echo(json.dumps(payload, indent=2))
    else:
        for result in results:
            click.echo(f"[weights] {result.path} — suspected={result.suspected}")
            for tensor in result.tensors:
                click.echo(
                    f"  tensor={tensor.name} dtype={tensor.dtype} lsb_bias={tensor.lsb_ones_ratio:.3f}"
                    f" poison={tensor.suspected_poison} steg={tensor.suspected_steg}"
                )

    if fail_on_suspect and any(r.suspected for r in results):
        raise SystemExit(1)


@main.command()
@click.argument("checkpoints", nargs=-1, type=click.Path(exists=True, dir_okay=False, path_type=str))
@click.option("--json", "json_output", is_flag=True, help="Emit JSON instead of human text.")
@click.option(
    "--fail-on-suspect",
    is_flag=True,
    help="Exit non-zero if any pickle file references dangerous globals.",
)
@click.option(
    "--max-bytes",
    type=int,
    default=10_000_000,
    show_default=True,
    help="Maximum allowed pickle size in bytes before aborting the scan (0 disables the limit).",
)
def pickles(
    checkpoints: tuple[str, ...],
    json_output: bool,
    fail_on_suspect: bool,
    max_bytes: int,
) -> None:
    """Inspect pickle-based checkpoints for unsafe globals or system calls."""

    if not checkpoints:
        click.echo("No pickle files supplied; nothing to inspect.", err=True)
        raise SystemExit(1)

    limit = None if max_bytes <= 0 else max_bytes
    try:
        results = inspect_pickle_files(checkpoints, max_bytes=limit)
    except PickleFileTooLargeError as exc:
        click.echo(str(exc), err=True)
        raise SystemExit(1) from exc

    if json_output:
        payload = [result.as_dict() for result in results]
        click.echo(json.dumps(payload, indent=2))
    else:
        for result in results:
            click.echo(f"[pickle] {result.path} — suspected={result.suspected}")
            for finding in result.findings:
                click.echo(f"  opcode={finding.opcode} module={finding.module} symbol={finding.name}")

    if fail_on_suspect and any(r.suspected for r in results):
        raise SystemExit(1)


@main.command()
@click.argument("base", type=click.Path(exists=True, dir_okay=False, path_type=str))
@click.argument("target", type=click.Path(exists=True, dir_okay=False, path_type=str))
def diff(base: str, target: str) -> None:
    """Compare two AI-BOM JSON reports and surface drift."""

    base_data = json.loads(Path(base).read_text())
    target_data = json.loads(Path(target).read_text())

    summary = diff_reports(base_data, target_data)

    click.echo("Dependency changes:")
    click.echo(
        f"  Added: {', '.join(summary['added_dependencies']) if summary['added_dependencies'] else 'none'}"
    )
    click.echo(
        f"  Removed: {', '.join(summary['removed_dependencies']) if summary['removed_dependencies'] else 'none'}"
    )
    click.echo(
        f"  Changed risk: {', '.join(summary['changed_dependencies']) if summary['changed_dependencies'] else 'none'}"
    )
    click.echo(f"Stack risk delta: {summary['stack_risk_delta']}")


if __name__ == "__main__":
    main()
