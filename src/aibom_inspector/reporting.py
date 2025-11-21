from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from jinja2 import Environment, select_autoescape

from .types import Report


env = Environment(autoescape=select_autoescape(["html", "xml"]))


def _dependency_rows(report: Report) -> Iterable[dict]:
    for dep in report.dependencies:
        yield {
            "name": dep.name,
            "version": dep.version or "unversioned",
            "source": dep.source,
            "issues": [issue.message for issue in dep.issues],
            "risk": dep.risk_score,
        }


def _model_rows(report: Report) -> Iterable[dict]:
    for model in report.models:
        yield {
            "id": model.identifier,
            "source": model.source,
            "license": model.license or "unknown",
            "last_updated": model.last_updated.isoformat() if model.last_updated else "unknown",
            "issues": [issue.message for issue in model.issues],
            "risk": model.risk_score,
        }


def render_json(report: Report) -> str:
    payload = {
        "generated_at": report.generated_at.isoformat(),
        "ai_summary": report.ai_summary,
        "total_risk": report.total_risk,
        "stack_risk_score": report.stack_risk_score,
        "risk_breakdown": report.risk_breakdown,
        "dependencies": list(_dependency_rows(report)),
        "models": list(_model_rows(report)),
    }
    return json.dumps(payload, indent=2)


def render_markdown(report: Report) -> str:
    lines = [
        "# AI-BOM Report",
        "",
        f"Generated at: {report.generated_at.isoformat()}",
        f"Stack Risk Score: {report.stack_risk_score}/100",
    ]
    if report.ai_summary:
        lines.append("\n## AI Summary\n")
        lines.append(report.ai_summary)

    lines.append("\n## Dependencies\n")
    lines.append("| Name | Version | Source | Risk | Issues |")
    lines.append("| --- | --- | --- | --- | --- |")
    for row in _dependency_rows(report):
        issues = "; ".join(row["issues"]) or "None"
        lines.append(
            f"| {row['name']} | {row['version']} | {row['source']} | {row['risk']} | {issues} |"
        )

    lines.append("\n## Models\n")
    lines.append("| ID | Source | License | Last Updated | Risk | Issues |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for row in _model_rows(report):
        issues = "; ".join(row["issues"]) or "None"
        lines.append(
            f"| {row['id']} | {row['source']} | {row['license']} | {row['last_updated']} | {row['risk']} | {issues} |"
        )

    return "\n".join(lines)


def render_html(report: Report) -> str:
    template = env.from_string(
        """
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <title>AI-BOM Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 2rem; }
    h1, h2 { color: #1f2937; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }
    th, td { border: 1px solid #d1d5db; padding: 0.5rem; }
    th { background: #f3f4f6; text-align: left; }
    .risk { font-weight: bold; }
    .badge { display: inline-block; padding: 0.35rem 0.6rem; border-radius: 0.4rem; font-weight: 600; color: #111827; }
    .badge.good { background: #d1fae5; }
    .badge.warn { background: #fef3c7; }
    .badge.bad { background: #fee2e2; }
  </style>
</head>
<body>
  <h1>AI-BOM Report</h1>
  <p>Generated at: {{ generated_at }}</p>
  <p>Stack Risk Score: <span class=\"badge {{ badge_class }}\">{{ stack_risk_score }} / 100</span></p>
  {% if ai_summary %}
  <section>
    <h2>AI Summary</h2>
    <p>{{ ai_summary }}</p>
  </section>
  {% endif %}
  <section>
    <h2>Dependencies</h2>
    <table>
      <thead><tr><th>Name</th><th>Version</th><th>Source</th><th>Risk</th><th>Issues</th></tr></thead>
      <tbody>
        {% for row in dependencies %}
        <tr>
          <td>{{ row.name }}</td>
          <td>{{ row.version }}</td>
          <td>{{ row.source }}</td>
          <td class=\"risk\">{{ row.risk }}</td>
          <td>{{ row.issues | join('; ') if row.issues else 'None' }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </section>
  <section>
    <h2>Models</h2>
    <table>
      <thead><tr><th>ID</th><th>Source</th><th>License</th><th>Last Updated</th><th>Risk</th><th>Issues</th></tr></thead>
      <tbody>
        {% for row in models %}
        <tr>
          <td>{{ row.id }}</td>
          <td>{{ row.source }}</td>
          <td>{{ row.license }}</td>
          <td>{{ row.last_updated }}</td>
          <td class=\"risk\">{{ row.risk }}</td>
          <td>{{ row.issues | join('; ') if row.issues else 'None' }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </section>
</body>
</html>
"""
    )

    return template.render(
        generated_at=report.generated_at.isoformat(),
        ai_summary=report.ai_summary,
        stack_risk_score=report.stack_risk_score,
        badge_class="good" if report.stack_risk_score >= 80 else ("warn" if report.stack_risk_score >= 50 else "bad"),
        dependencies=list(_dependency_rows(report)),
        models=list(_model_rows(report)),
    )


def render_report(report: Report, fmt: str) -> str:
    fmt = fmt.lower()
    if fmt == "json":
        return render_json(report)
    if fmt in {"md", "markdown"}:
        return render_markdown(report)
    if fmt == "html":
        return render_html(report)
    raise ValueError(f"Unknown report format: {fmt}")


def write_report(report: Report, fmt: str, destination: Path | None) -> str:
    output = render_report(report, fmt)
    if destination:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(output)
    return output
