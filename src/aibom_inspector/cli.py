from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

import click

from .dependency_scanner import (
    scan_go_mod,
    scan_package_json,
    scan_package_lock,
    scan_pom,
    scan_pyproject,
    scan_requirements,
)
from .model_inspector import scan_models_from_file, summarize_models
from .reporting import write_report
from .types import Report


def _collect_dependencies(
    requirements: Optional[str],
    pyproject: Optional[str],
    extra_manifests: tuple[str, ...],
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
    "--format",
    "fmt",
    type=click.Choice(["json", "markdown", "md", "html"], case_sensitive=False),
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
    models_file: Optional[str],
    model_id: tuple[str, ...],
    manifest: tuple[str, ...],
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

    dependencies = _collect_dependencies(requirements_path, pyproject_path, manifest)

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
