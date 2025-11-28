# Policy enforcement

Policies let teams codify their risk appetite for dependencies and models. They are YAML documents that match `schemas/policy.schema.json` and can be loaded with `aibom_inspector.policy.load_policy`.

## Fields

- `min_score` – minimum acceptable stack risk score (0–100).
- `max_cves` – number of CVE/advisory hits allowed before failing.
- `disallow`/`blocklist` – issue codes that should immediately fail policy checks (e.g., `MISSING_PIN`, `UNVERIFIED_SOURCE`).
- `min_trust_score` – minimum trust score for dependencies/models (0–100).
- `publisher_expectations` – map of component names to expected publishers or sources.
- `exceptions` – allowlist entries that can soften strict rules with optional expiration timestamps.

## Examples

Starter policies live in `policies/examples/`:

- `default.yml` sets modest minimum scores and disallows unpinned dependencies.
- `strict.yml` blocks unverified sources, stale models, and unknown licenses.
- `oss-friendly.yml` favors permissive defaults while still rejecting known vulnerabilities.

## GitHub checks

Use `aibom_inspector.policy.write_github_check` to emit a JSON payload suitable for GitHub Checks API integrations. The helper includes the evaluation outcome, stack risk score, and a compact summary of failures.
