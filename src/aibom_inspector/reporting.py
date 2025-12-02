from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Iterable
from uuid import uuid4

from jinja2 import Environment, select_autoescape

from .stack_discovery import snapshot_as_dict
from .types import Report


env = Environment(autoescape=select_autoescape(["html", "xml"]))


def _dependency_rows(report: Report) -> Iterable[dict]:
    for dep in report.dependencies:
        issue_details = [
            {"message": issue.message, "severity": issue.severity, "code": issue.code} for issue in dep.issues
        ]
        yield {
            "name": dep.name,
            "version": dep.version or "unversioned",
            "source": dep.source,
            "license": dep.license or "unknown",
            "license_category": dep.license_category or "unknown",
            "issues": [issue["message"] for issue in issue_details],
            "issue_details": issue_details,
            "risk": dep.risk_score,
            "trust_signals": [
                {"message": signal.message, "severity": signal.severity, "code": signal.code}
                for signal in dep.trust_signals
            ],
            "trust_score": dep.trust_score,
        }


def _model_rows(report: Report) -> Iterable[dict]:
    for model in report.models:
        issue_details = [
            {"message": issue.message, "severity": issue.severity, "code": issue.code}
            for issue in model.issues
        ]
        yield {
            "id": model.identifier,
            "source": model.source,
            "license": model.license or "unknown",
            "license_category": model.license_category or "unknown",
            "last_updated": model.last_updated.isoformat() if model.last_updated else "unknown",
            "issues": [issue["message"] for issue in issue_details],
            "issue_details": issue_details,
            "risk": model.risk_score,
            "trust_signals": [
                {"message": signal.message, "severity": signal.severity, "code": signal.code}
                for signal in model.trust_signals
            ],
            "trust_score": model.trust_score,
        }


def render_json(report: Report) -> str:
    payload = {
        "generated_at": report.generated_at.isoformat(),
        "ai_summary": report.ai_summary,
        "total_risk": report.total_risk,
        "stack_risk_score": report.stack_risk_score,
        "risk_breakdown": report.risk_breakdown,
        "risk_settings": report.risk_settings.as_dict(),
        "dependencies": list(_dependency_rows(report)),
        "models": list(_model_rows(report)),
    }
    if report.stack_snapshot:
        payload["stack"] = snapshot_as_dict(report.stack_snapshot)
    if report.graph_policy_violations:
        payload["graph_policy_violations"] = [asdict(v) for v in report.graph_policy_violations]
    return json.dumps(payload, indent=2)


def render_markdown(report: Report) -> str:
    lines = [
        "# AI-BOM Report",
        "",
        f"Generated at: {report.generated_at.isoformat()}",
        f"Stack Risk Score: {report.stack_risk_score}/{report.risk_settings.max_score}",
    ]
    if report.ai_summary:
        lines.append("\n## AI Summary\n")
        lines.append(report.ai_summary)

    lines.append("\n## Dependencies\n")
    lines.append("| Name | Version | Source | License | Risk | Trust | Issues |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for row in _dependency_rows(report):
        issues = "; ".join(f"{detail['message']} ({detail['severity']})" for detail in row["issue_details"])
        issues = issues or "None"
        lines.append(
            f"| {row['name']} | {row['version']} | {row['source']} | {row['license']} ({row['license_category']}) | {row['risk']} | {row['trust_score']} | {issues} |"
        )

    lines.append("\n## Models\n")
    lines.append("| ID | Source | License | Last Updated | Risk | Trust | Issues |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for row in _model_rows(report):
        issues = "; ".join(f"{detail['message']} ({detail['severity']})" for detail in row["issue_details"])
        issues = issues or "None"
        lines.append(
            f"| {row['id']} | {row['source']} | {row['license']} | {row['last_updated']} | {row['risk']} | {row['trust_score']} | {issues} |"
        )

    if report.stack_snapshot:
        lines.append("\n## Stack discovery\n")
        lines.append("| Kind | ID | Evidence | Metadata |")
        lines.append("| --- | --- | --- | --- |")
        for node in report.stack_snapshot.nodes:
            metadata = ", ".join(f"{k}={v}" for k, v in node.metadata.items()) or "None"
            evidence = node.metadata.get("evidence", "") if isinstance(node.metadata, dict) else ""
            lines.append(f"| {node.kind} | {node.id} | {evidence} | {metadata} |")

    if report.graph_policy_violations:
        lines.append("\n## Graph policy violations\n")
        lines.append("| ID | Severity | Message | Evidence | Suggested fixes |")
        lines.append("| --- | --- | --- | --- | --- |")
        for violation in report.graph_policy_violations:
            evidence = "; ".join(violation.evidence) if violation.evidence else "None"
            fixes = "; ".join(violation.suggested_fixes) if violation.suggested_fixes else "None"
            lines.append(
                f"| {violation.id} | {violation.severity} | {violation.message} | {evidence} | {fixes} |"
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
    .badge.good { background: #d1fae5; color: #065f46; }
    .badge.warn { background: #fef3c7; color: #92400e; }
    .badge.bad { background: #fee2e2; color: #991b1b; }
    .badge.sev-high { background: #fee2e2; color: #991b1b; }
    .badge.sev-medium { background: #fef3c7; color: #92400e; }
    .badge.sev-low { background: #e0f2fe; color: #0369a1; }
    .issue-text { margin-left: 0.35rem; }
  </style>
</head>
<body>
  <h1>AI-BOM Report</h1>
  <p>Generated at: {{ generated_at }}</p>
  <p>Stack Risk Score: <span class=\"badge {{ badge_class }}\">{{ stack_risk_score }} / {{ max_score }}</span></p>
  {% if ai_summary %}
  <section>
    <h2>AI Summary</h2>
    <p>{{ ai_summary }}</p>
  </section>
  {% endif %}
  {% if stack %}
  <section>
    <h2>Stack discovery</h2>
    <table>
      <thead><tr><th>Kind</th><th>ID</th><th>Evidence</th><th>Metadata</th></tr></thead>
      <tbody>
        {% for node in stack.nodes %}
        <tr>
          <td>{{ node.kind }}</td>
          <td>{{ node.id }}</td>
          <td>{{ node.metadata.get('evidence', '') }}</td>
          <td>{{ node.metadata }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </section>
  {% endif %}
  <section>
    <h2>Dependencies</h2>
    <table>
      <thead><tr><th>Name</th><th>Version</th><th>Source</th><th>License</th><th>Risk</th><th>Trust</th><th>Issues</th></tr></thead>
      <tbody>
        {% for row in dependencies %}
        <tr>
          <td>{{ row.name }}</td>
          <td>{{ row.version }}</td>
          <td>{{ row.source }}</td>
          <td>{{ row.license }} ({{ row.license_category }})</td>
          <td class=\"risk\">{{ row.risk }}</td>
          <td class=\"risk\">{{ row.trust_score }}</td>
          <td>
            {% if row.issue_details %}
              {% for issue in row.issue_details %}
                <span class=\"badge sev-{{ issue.severity }}\">{{ issue.severity.title() }}</span>
                <span class=\"issue-text\">{{ issue.message }}</span>{% if not loop.last %}<br />{% endif %}
              {% endfor %}
            {% else %}
              None
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </section>
  <section>
    <h2>Models</h2>
    <table>
      <thead><tr><th>ID</th><th>Source</th><th>License</th><th>Last Updated</th><th>Risk</th><th>Trust</th><th>Issues</th></tr></thead>
      <tbody>
        {% for row in models %}
        <tr>
          <td>{{ row.id }}</td>
          <td>{{ row.source }}</td>
          <td>{{ row.license }}</td>
          <td>{{ row.last_updated }}</td>
          <td class=\"risk\">{{ row.risk }}</td>
          <td class=\"risk\">{{ row.trust_score }}</td>
          <td>
            {% if row.issue_details %}
              {% for issue in row.issue_details %}
                <span class=\"badge sev-{{ issue.severity }}\">{{ issue.severity.title() }}</span>
                <span class=\"issue-text\">{{ issue.message }}</span>{% if not loop.last %}<br />{% endif %}
              {% endfor %}
            {% else %}
              None
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </section>
  {% if graph_violations %}
  <section>
    <h2>Graph policy violations</h2>
    <table>
      <thead><tr><th>ID</th><th>Severity</th><th>Message</th><th>Evidence</th><th>Suggested fixes</th></tr></thead>
      <tbody>
        {% for violation in graph_violations %}
        <tr>
          <td>{{ violation.id }}</td>
          <td>{{ violation.severity }}</td>
          <td>{{ violation.message }}</td>
          <td>{{ "; ".join(violation.evidence) if violation.evidence else "" }}</td>
          <td>{{ "; ".join(violation.suggested_fixes) if violation.suggested_fixes else "" }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </section>
  {% endif %}
</body>
</html>
"""
    )

    return template.render(
        generated_at=report.generated_at.isoformat(),
        ai_summary=report.ai_summary,
        stack_risk_score=report.stack_risk_score,
        badge_class=(
            "bad"
            if (
                report.risk_breakdown.get("cves", 0) > 0
                or (
                    report.risk_breakdown.get("unpinned_deps", 0)
                    + report.risk_breakdown.get("unverified_sources", 0)
                )
                >= 2
            )
            else (
                "good"
                if report.stack_risk_score >= 80
                else ("warn" if report.stack_risk_score >= 50 else "bad")
            )
        ),
        max_score=report.risk_settings.max_score,
        dependencies=list(_dependency_rows(report)),
        models=list(_model_rows(report)),
        stack=snapshot_as_dict(report.stack_snapshot) if report.stack_snapshot else None,
        graph_violations=[asdict(v) for v in report.graph_policy_violations],
    )


def render_cyclonedx(report: Report) -> str:
    components = []
    for row in _dependency_rows(report):
        components.append(
            {
                "type": "library",
                "name": row["name"],
                "version": row["version"],
                "licenses": [{"license": {"id": row["license"] if row["license"] else "UNKNOWN"}}],
                "properties": [
                    {"name": "aibom:source", "value": row["source"]},
                    {"name": "aibom:license_category", "value": row["license_category"]},
                    {"name": "aibom:risk", "value": row["risk"]},
                    {"name": "aibom:issues", "value": "; ".join(row["issues"])},
                ],
            }
        )

    for model in _model_rows(report):
        components.append(
            {
                "type": "application",
                "name": model["id"],
                "version": model["last_updated"],
                "licenses": [{"license": {"id": model["license"] if model["license"] else "UNKNOWN"}}],
                "properties": [
                    {"name": "aibom:source", "value": model["source"]},
                    {"name": "aibom:license_category", "value": model["license_category"]},
                    {"name": "aibom:risk", "value": model["risk"]},
                    {"name": "aibom:issues", "value": "; ".join(model["issues"])},
                ],
            }
        )

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"tools": [{"vendor": "aibom", "name": "AI-BOM Inspector"}]},
        "components": components,
    }
    return json.dumps(sbom, indent=2)


def render_spdx(report: Report) -> str:
    packages = []
    for row in _dependency_rows(report):
        packages.append(
            {
                "name": row["name"],
                "SPDXID": f"SPDXRef-{uuid4().hex[:8]}",
                "versionInfo": row["version"],
                "licenseDeclared": row["license"],
                "licenseConcluded": row["license"],
                "summary": "; ".join(row["issues"]),
            }
        )

    for model in _model_rows(report):
        packages.append(
            {
                "name": f"model:{model['id']}",
                "SPDXID": f"SPDXRef-{uuid4().hex[:8]}",
                "versionInfo": model["last_updated"],
                "licenseDeclared": model["license"],
                "licenseConcluded": model["license"],
                "summary": "; ".join(model["issues"]),
            }
        )

    spdx = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "AI-BOM Inspector SBOM",
        "packages": packages,
    }
    return json.dumps(spdx, indent=2)


def _sarif_level(severity: str) -> str:
    match severity.lower():
        case "high":
            return "error"
        case "low":
            return "note"
        case _:
            return "warning"


def _sarif_result(target: str, name: str, issue: dict) -> dict:
    rule_id = (issue.get("code") or issue.get("message") or "AIBOM_ISSUE").replace(" ", "_")[:64]
    return {
        "ruleId": rule_id,
        "level": _sarif_level(issue.get("severity", "warning")),
        "message": {"text": issue.get("message", "AI-BOM Inspector finding")},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f"{target}:{name}"},
                }
            }
        ],
    }


def render_sarif(report: Report) -> str:
    results: list[dict] = []
    rules: dict[str, dict] = {}

    for row in _dependency_rows(report):
        for issue in row["issue_details"]:
            results.append(_sarif_result("dependency", row["name"], issue))
            rule_id = (issue.get("code") or issue.get("message") or "AIBOM_ISSUE").replace(" ", "_")[:64]
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": issue.get("message", "AI-BOM Inspector finding")},
                    "fullDescription": {
                        "text": "Dependency policy finding produced by AI-BOM Inspector's guardrails.",
                    },
                    "helpUri": "https://github.com/aibom-inspector/AI-BOM-Inspector/blob/main/docs/POLICY_COOKBOOK.md",
                    "properties": {"aibom:severity": issue.get("severity", "warning")},
                },
            )

    for model in _model_rows(report):
        for issue in model["issue_details"]:
            results.append(_sarif_result("model", model["id"], issue))
            rule_id = (issue.get("code") or issue.get("message") or "AIBOM_ISSUE").replace(" ", "_")[:64]
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": issue.get("message", "AI-BOM Inspector finding")},
                    "fullDescription": {
                        "text": "Model policy finding produced by AI-BOM Inspector's guardrails.",
                    },
                    "helpUri": "https://github.com/aibom-inspector/AI-BOM-Inspector/blob/main/docs/POLICY_COOKBOOK.md",
                    "properties": {"aibom:severity": issue.get("severity", "warning")},
                },
            )

    for violation in report.graph_policy_violations:
        rule_id = f"graph_{violation.id}"[:64]
        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(violation.severity),
                "message": {"text": violation.message},
                "properties": {
                    "aibom:evidence": violation.evidence,
                    "aibom:suggested_fixes": violation.suggested_fixes,
                },
            }
        )
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": violation.message},
                "fullDescription": {
                    "text": "Graph policy guardrail violation (agents, tools, providers, MCP permissions).",
                },
                "helpUri": "https://github.com/aibom-inspector/AI-BOM-Inspector/blob/main/docs/POLICY.md",
                "properties": {"aibom:severity": violation.severity},
            },
        )

    graph_violations = [asdict(v) for v in report.graph_policy_violations]

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "aibom-inspector", "rules": list(rules.values())}},
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "aibom:stack_risk_score": report.stack_risk_score,
                            "aibom:risk_breakdown": report.risk_breakdown,
                            "aibom:graph_policy_violations": graph_violations,
                        },
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def render_report(report: Report, fmt: str) -> str:
    fmt = fmt.lower()
    if fmt == "json":
        return render_json(report)
    if fmt in {"md", "markdown"}:
        return render_markdown(report)
    if fmt == "html":
        return render_html(report)
    if fmt == "sarif":
        return render_sarif(report)
    if fmt == "cyclonedx":
        return render_cyclonedx(report)
    if fmt == "spdx":
        return render_spdx(report)
    raise ValueError(f"Unknown report format: {fmt}")


def write_report(report: Report, fmt: str, destination: Path | None) -> str:
    output = render_report(report, fmt)
    if destination:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(output)
    return output
