# AI-BOM extensions and JSON schema

AI-BOM Inspector emits a JSON report and can export CycloneDX/SPDX SBOMs with AI-aware extensions so downstream tools can keep model metadata next to software dependencies.

## Core JSON report shape
- `generated_at` (ISO8601 string): timestamp of report generation.
- `stack_risk_score` (int): health score from 0–100 after penalties.
- `risk_breakdown` (object): counts of `unpinned_deps`, `unverified_sources`, `unknown_licenses`, `stale_models`, `cves`.
- `risk_settings` (object):
  - `max_score` (int)
  - `severity_penalties` (object): `high`, `medium`, `low` integers
  - `governance_penalty` (int)
  - `cve_penalty` (int)
- `stack` (object, optional): normalized discovery results with `nodes`, `edges`, and `context` (e.g., `env`).
- `graph_policy_violations` (array, optional): violations emitted by default graph guardrails with `id`, `severity`, `message`, `evidence`, and `suggested_fixes`.
- `ai_summary` (string|null): human-readable placeholder text; intended to be replaced by your own LLM integration.
- `dependencies` (array):
  - `name` (string)
  - `version` (string; includes comparator, e.g., `==1.2.3`)
  - `source` (string; manifest file or `cyclonedx`/`spdx` when imported)
  - `license` (string)
  - `license_category` (string; `permissive`, `copyleft`, `proprietary`, `unknown`)
  - `issues` (array of strings)
  - `issue_details` (array of objects with `message`, `severity`, optional `code`)
  - `risk` (int; points deducted for this dependency)
- `models` (array):
  - `id` (string)
  - `source` (string; e.g., `huggingface`, `private`)
  - `license` (string)
  - `license_category` (string)
  - `last_updated` (ISO8601 string)
  - `issues`, `issue_details`, `risk` (same shape as dependencies)

## CycloneDX mapping
- Each dependency is exported as a `library` component; each model is exported as an `application` component.
- AI-BOM extensions are carried as custom properties:
  - `aibom:source`
  - `aibom:license_category`
  - `aibom:risk`
  - `aibom:issues` (semicolon-separated list)
- License metadata is emitted through the standard CycloneDX `licenses` block, defaulting to `UNKNOWN` when missing.

## SPDX mapping
- Each dependency is exported as a package with `name`, `SPDXID`, `versionInfo`, `licenseDeclared`, and `licenseConcluded`.
- Each model is exported as a package named `model:<id>` with the same license fields.
- AI-BOM issues are summarized in the SPDX `summary` field; SPDX does not carry the custom `aibom:*` property bag, so use the JSON report or CycloneDX export when you need per-field extension data.

## Extension rationale
These extensions keep AI-specific provenance (model sources, license categories, risk points, and issues) available even when SBOM formats do not model them natively. Downstream consumers can parse the JSON report directly or read the custom CycloneDX properties to preserve AI-BOM context.
