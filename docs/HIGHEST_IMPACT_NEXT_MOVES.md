# Highest-impact feature bets

Ship these features to make AI-BOM Inspector feel native in CI/CD and GitHub while tightening the policy UX.

## Tiered upgrade plan (Perception + Authority → Market weapon)
Prioritize these tiers in order to move from scanner utility to governance platform. Each tier builds on the last by adding compliance mapping, trust signals, and executive-ready risk framing.

### Tier 1: Perception + Authority
- **Framework mapping (huge ROI)**: map findings to governance frameworks such as **NIST AI RMF**, **ISO/IEC 42001**, **OWASP Top 10 for LLMs**, and (where applicable) **SOC 2 Trust Criteria**. Report entries should directly show mappings (e.g., “Finding X → NIST AI RMF 1.2, ISO 42001 A.5.3”). This turns results into compliance evidence, not just scanner output.
- **Provenance & attestation (trust layer)**: hash inputs/outputs, tie findings to git commit SHA, support optional signing, and emit machine-readable attestation JSON. This positions the tool for SLSA/in-toto style workflows.
- **Completeness & confidence scoring**: add coverage %, static vs runtime visibility flags, and an “unobservable areas” section (e.g., “78% static coverage; runtime model loading: unknown; env-based selection: unobservable”). This transparency builds auditor trust.

### Tier 2: Technical maturity
- **Runtime hooks / tracing (differentiator)**: optional Python import tracing, wrappers for model load calls, and LD_PRELOAD/monkeypatch style tracing to capture runtime-resolved models.
- **Enterprise CI/CD modes**: provide hardened presets for GitHub Actions, GitLab CI, and Azure DevOps with policy-linked exit codes, artifact storage, and JSON outputs that plug into GRC tooling.

## Enterprise trust baseline (non-negotiables)
These controls are the deal-makers for regulated and enterprise buyers. See `docs/ENTERPRISE_TRUST_BASELINE.md` for the full checklist and rationale.

### Provenance & signing
- Cosign-signed releases and build attestations.
- SLSA-aligned CI pipeline support.
- Reproducible builds for independent verification.

### Artifact integrity
- Runtime hash verification for reports/attestations.
- Signed plugins/extensions.
- Config + ruleset integrity checks.

### Dependency trust enforcement
- Signature verification on dependencies.
- Trusted registry allowlists.
- Dependency confusion detection.
- Lockfile checksum enforcement.

### Tier 3: Market weapon
- **Risk scoring that execs understand**: translate findings into Low/Medium/High governance risk, regulatory exposure, and supply-chain blast radius.
- **SBOM + AI-BOM correlation**: connect traditional SBOMs (CycloneDX, SPDX) to AI-BOM artifacts to show “this vulnerable lib supports this model pipeline.”

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
