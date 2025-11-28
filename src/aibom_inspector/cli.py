from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Optional
from datetime import datetime
import click

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
from .policy import diff_reports, evaluate_policy, load_policy, write_evidence_pack, write_github_check
from .reporting import render_report, write_report
from .tensor_fuzz import inspect_weight_files
from .types import Report, RiskSettings


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
    type=click.Choice(["json", "markdown", "md", "html", "cyclonedx", "spdx"], case_sensitive=False),
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
    "--sign-report",
    is_flag=True,
    help="Emit a SHA256 signature alongside the rendered report for tamper evidence.",
)
@click.option(
    "--baseline-report",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Previous JSON report to diff against for change detection.",
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
    shadow_uefi_timeout: Optional[float],
    shadow_uefi_repo: Optional[str],
    require_input: bool,
    policy: Optional[str],
    github_check_output: Optional[str],
    evidence_pack: Optional[str],
    sign_report: bool,
    baseline_report: Optional[str],
) -> None:
    """Scan dependencies, models, and produce a report."""
    requirements_path = requirements or (
        str(Path("requirements.txt")) if Path("requirements.txt").exists() else None
    )
    pyproject_path = pyproject or (
        str(Path("pyproject.toml")) if Path("pyproject.toml").exists() else None
    )

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

    if not dependencies and not models:
        click.echo("No dependencies or models detected; nothing to scan.", err=True)
        if require_input:
            raise SystemExit(1)

    if with_cves:
        dependencies = enrich_with_osv(
            dependencies, offline=offline, osv_url=osv_url, timeout=osv_timeout
        )

    models = enrich_models_with_cves(models)

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

    report = Report(
        dependencies=dependencies,
        models=models,
        generated_at=datetime.utcnow(),
        ai_summary=summary,
        risk_settings=risk_settings,
    )

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

    policy_evaluation = None
    report_json = json.loads(render_report(report, "json"))
    baseline_diff = None
    if baseline_report:
        try:
            base_data = json.loads(Path(baseline_report).read_text())
            baseline_diff = diff_reports(base_data, report_json)
        except Exception as exc:  # pragma: no cover - I/O heavy
            click.echo(f"Unable to diff with baseline report: {exc}", err=True)

    if policy:
        policy_data = load_policy(Path(policy))
        policy_evaluation = evaluate_policy(report, policy_data)
        if github_check_output:
            write_github_check(Path(github_check_output), policy_evaluation, report)
        if not policy_evaluation.passed:
            raise SystemExit(1)

    if fail_on_score is not None:
        if report.stack_risk_score < fail_on_score:
            raise SystemExit(1)

    signature_text = None
    if sign_report:
        digest = hashlib.sha256(rendered.encode()).hexdigest()
        sig_path = (report_path or Path(f"aibom-report.{fmt}")).with_suffix(
            (report_path or Path(f"aibom-report.{fmt}")).suffix + ".sha256"
        )
        sig_path.parent.mkdir(parents=True, exist_ok=True)
        sig_path.write_text(digest)
        signature_text = digest

    if evidence_pack:
        write_evidence_pack(
            Path(evidence_pack),
            rendered,
            report_path or Path(f"aibom-report.{fmt}"),
            policy_evaluation,
            Path(policy) if policy else None,
            baseline_diff,
            signature_text,
        )


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
@click.argument("base", type=click.Path(exists=True, dir_okay=False, path_type=str))
@click.argument("target", type=click.Path(exists=True, dir_okay=False, path_type=str))
def diff(base: str, target: str) -> None:
    """Compare two AI-BOM JSON reports and surface drift."""

    base_data = json.loads(Path(base).read_text())
    target_data = json.loads(Path(target).read_text())

    summary = diff_reports(base_data, target_data)

    click.echo("Dependency changes:")
    click.echo(f"  Added: {', '.join(summary['added_dependencies']) if summary['added_dependencies'] else 'none'}")
    click.echo(f"  Removed: {', '.join(summary['removed_dependencies']) if summary['removed_dependencies'] else 'none'}")
    click.echo(f"  Changed risk: {', '.join(summary['changed_dependencies']) if summary['changed_dependencies'] else 'none'}")
    click.echo(f"Stack risk delta: {summary['stack_risk_delta']}")


if __name__ == "__main__":
    main()
