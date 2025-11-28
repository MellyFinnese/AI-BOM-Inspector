# FAQ

## Does the scanner call external services by default?

No. The default posture is offline (`--offline`). Optional enrichments such as OSV CVE lookups or Hugging Face metadata only trigger when you pass `--online` and enable specific flags (e.g., `--with-cves`).

## How do I use custom policies?

Place a YAML policy that matches `schemas/policy.schema.json` anywhere in your repo and load it with `aibom_inspector.policy.load_policy`. Starter examples live in `policies/examples/`.

## Where do GitHub integrations live now?

Reusable automation lives under `integrations/`:

- `integrations/github-action` exposes a composite action used by `.github/workflows/scan-pr.yml`.
- `integrations/pre-commit` ships a local hook definition you can copy into `.pre-commit-config.yaml`.

## What file formats can the reporter emit?

Run `aibom scan --help` to see the full list. JSON, Markdown, and HTML are built in; CycloneDX/SPDX exports are also supported for SBOM workflows.
