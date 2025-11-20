from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

import click

from .dependency_scanner import scan_pyproject, scan_requirements
from .model_inspector import scan_models_from_file, summarize_models
from .reporting import write_report
from .types import Report


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
def scan(requirements: Optional[str], pyproject: Optional[str], models_file: Optional[str], model_id: tuple[str, ...], fmt: str, output: Optional[str], ai_summary: bool) -> None:
    """Scan dependencies, models, and produce a report."""
    requirements_path = requirements or (
        str(Path("requirements.txt")) if Path("requirements.txt").exists() else None
    )
    pyproject_path = pyproject or (str(Path("pyproject.toml")) if Path("pyproject.toml").exists() else None)

    dependencies = _collect_dependencies(requirements_path, pyproject_path)
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


if __name__ == "__main__":
    main()
