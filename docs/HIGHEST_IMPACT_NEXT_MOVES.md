# Highest-impact feature bets

Ship these features to make AI-BOM Inspector feel native in CI/CD and GitHub while tightening the policy UX.

## Feature: Auto-discover → enforce loop
- **`aibom discover`**: crawl the repo to auto-detect dependency manifests, SBOMs, and model metadata files; emit a normalized AI-BOM that can be checked in or cached.
- **`aibom enforce`**: regenerate the AI-BOM, apply policies, and surface pass/fail + diff against the previous run (or a stored baseline). Gate on score, issue codes, or policy allowlists.
- **CI workflow**: run `discover` in main to persist the baseline AI-BOM artifact; run `enforce` on PRs to block regressions, show diffs, and optionally upload SARIF for code scanning.

## Feature: Policy-as-code UX
- **`aibom init`**: scaffold a project-local policy bundle (baseline policy + allowlists) with sensible defaults, comments, and links to the policy cookbook.
- **`aibom explain <ISSUE_CODE>`**: print issue rationale, impact, and remediation guidance directly in the CLI, linking to docs when deeper context is needed.
- **Recommended remediations**: ship canned fixes for high-churn findings (pinning guidance, license/notice examples, model freshness playbooks) that `explain` and reports can reference.

## Feature: GitHub-native outputs
- **First-class SARIF**: make `--format sarif` and the existing GitHub Action default to uploading SARIF so findings flow into code scanning without extra wiring.
- **Annotations + summaries**: mirror findings in job summaries and per-line annotations when file paths and package locations are available.
- **Diffable artifacts**: attach the AI-BOM, policy report, and diff as action artifacts so maintainers can review changes without re-running the scan locally.
