from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

import click

from .dependency_scanner import (
    enrich_with_osv,
    parse_sbom_file,
    run_pip_audit,
    scan_pyproject,
    scan_requirements,
)
from .model_inspector import scan_models_from_file, summarize_models
from .reporting import write_report
from .types import DependencyInfo, Report


def _collect_dependencies(requirements: Optional[str], pyproject: Optional[str]):
    deps = []
    if requirements:
        deps.extend(scan_requirements(Path(requirements)))
    if pyproject:
        deps.extend(scan_pyproject(Path(pyproject)))
    return deps


def _collect_models(models_file: Optional[str], model_ids: tuple[str, ...]):
    models = []
    if models_file:
        models.extend(scan_models_from_file(Path(models_file)))
    if model_ids:
        models.extend(summarize_models(list(model_ids)))
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
    "--sbom-file",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Existing SBOM (CycloneDX or SPDX JSON) to ingest instead of source files.",
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
    "--ai-summary",
    is_flag=True,
    help="Include a placeholder AI-generated summary (offline stub).",
)
@click.option(
    "--fail-on-score",
    type=int,
    help="Exit non-zero when calculated risk exceeds the threshold (0-100, higher = riskier).",
)
def scan(
    requirements: Optional[str],
    pyproject: Optional[str],
    sbom_file: Optional[str],
    models_file: Optional[str],
    model_id: tuple[str, ...],
    fmt: str,
    output: Optional[str],
    ai_summary: bool,
    fail_on_score: Optional[int],
) -> None:
    """Scan dependencies, models, and produce a report."""
    requirements_path = requirements or (
        str(Path("requirements.txt")) if Path("requirements.txt").exists() else None
    )
    pyproject_path = pyproject or (
        str(Path("pyproject.toml")) if Path("pyproject.toml").exists() else None
    )

    dependencies = _collect_dependencies(requirements_path, pyproject_path)
    if sbom_file:
        dependencies.extend(parse_sbom_file(Path(sbom_file)))

    dependencies = enrich_with_osv(dependencies)
    audit_issues = run_pip_audit(Path(requirements_path) if requirements_path else None)
    if audit_issues:
        for issue in audit_issues:
            target = next((d for d in dependencies if d.name in issue.message), None)
            if target:
                target.issues.append(issue)
            else:
                dependencies.append(
                    DependencyInfo(name="pip-audit", version=None, source="pip-audit", issues=[issue])
                )

    models = _collect_models(models_file, model_id)

    summary = None
    if ai_summary:
        summary = "AI summarization is disabled by default. Provide an LLM backend to enable rich summaries."

    report = Report(
        dependencies=dependencies,
        models=models,
        generated_at=datetime.utcnow(),
        ai_summary=summary,
    )

    destination = Path(output) if output else None
    rendered = write_report(report, fmt, destination)
    if not destination:
        click.echo(rendered)

    if fail_on_score is not None:
        risk_value = 100 - report.stack_risk_score
        if risk_value > fail_on_score:
            raise SystemExit(1)


@main.command()
@click.argument("base", type=click.Path(exists=True, dir_okay=False, path_type=str))
@click.argument("target", type=click.Path(exists=True, dir_okay=False, path_type=str))
def diff(base: str, target: str) -> None:
    """Compare two AI-BOM JSON reports and surface drift."""

    base_data = json.loads(Path(base).read_text())
    target_data = json.loads(Path(target).read_text())

    base_deps = {d["name"]: d for d in base_data.get("dependencies", [])}
    target_deps = {d["name"]: d for d in target_data.get("dependencies", [])}

    added = sorted(set(target_deps) - set(base_deps))
    removed = sorted(set(base_deps) - set(target_deps))

    changed = []
    for name in set(base_deps).intersection(target_deps):
        if base_deps[name].get("issues") != target_deps[name].get("issues"):
            changed.append(name)

    click.echo("Dependency changes:")
    click.echo(f"  Added: {', '.join(added) if added else 'none'}")
    click.echo(f"  Removed: {', '.join(removed) if removed else 'none'}")
    click.echo(f"  Changed risk: {', '.join(changed) if changed else 'none'}")


if __name__ == "__main__":
    main()
