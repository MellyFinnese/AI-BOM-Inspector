# Scoring

The scanner reports two related metrics:

- **Total risk** – sum of per-dependency and per-model risk scores.
- **Stack risk score** – a 0–100 health score derived from issue severity, governance findings, and CVE counts.

## Risk weights

See `aibom_inspector.types.RiskSettings` for tunable penalties:

- `severity_penalties`: defaults to 8 (high), 4 (medium), 2 (low).
- `governance_penalty`: defaults to 3 and is applied to unpinned dependencies and unverified sources.
- `cve_penalty`: defaults to 7 and is applied for CVE/advisory hits.

## Breakdowns

`Report.risk_breakdown` surfaces the categories that most influence the score:

- `unpinned_deps`
- `unverified_sources`
- `unknown_licenses`
- `stale_models`
- `cves`

These values also flow into the report JSON documented in `schemas/report.schema.json`.
