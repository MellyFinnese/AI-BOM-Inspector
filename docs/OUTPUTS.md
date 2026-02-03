# Output formats

This project emits JSON, SARIF, CycloneDX/SPDX, and provenance attestations so teams can plug the scanner into security workflows without custom glue. Below is a single scan represented in three formats.

## Side-by-side example

### JSON (scanner-native)
```json
{
  "stack_risk_score": 82,
  "executive_summary": {
    "governance_risk": "Medium",
    "regulatory_exposure": "Low",
    "supply_chain_blast_radius": "Low"
  },
  "completeness": {
    "static_coverage_pct": 100,
    "runtime_coverage_pct": 0,
    "static_visibility": true,
    "runtime_visibility": false,
    "unobservable_areas": ["Runtime model loading: unknown (no runtime trace supplied)"]
  },
  "risk_breakdown": {"unpinned_deps": 1, "unknown_licenses": 0, "stale_models": 0, "cves": 0},
  "dependencies": [
    {
      "name": "urllib3",
      "version": "1.26.18",
      "issues": ["[LOOSE_PIN] Dependency uses a version range"],
      "license": "mit"
    }
  ],
  "models": [
    {
      "id": "gpt2",
      "source": "huggingface",
      "issues": ["[STALE_MODEL] Model metadata is older than the freshness threshold"],
      "license": "mit"
    }
  ]
}
```
- **Best for**: programmatic consumption, `aibom diff`, and feeding into dashboards.
- **Schema**: enforced by `schemas/report.schema.json`.
- **Framework mappings**: each issue detail now includes NIST AI RMF / ISO 42001 / OWASP LLM / SOC 2 crosswalks for governance-ready reports.

### SARIF (security findings)
```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {"driver": {"name": "aibom-inspector"}},
      "results": [
        {
          "ruleId": "LOOSE_PIN",
          "message": {"text": "Dependency uses a version range"},
          "locations": [{"physicalLocation": {"artifactLocation": {"uri": "requirements.txt"}}}],
          "level": "warning"
        },
        {
          "ruleId": "STALE_MODEL",
          "message": {"text": "Model metadata is older than the freshness threshold"},
          "locations": [{"physicalLocation": {"artifactLocation": {"uri": "models.json"}}}],
          "level": "warning"
        }
      ]
    }
  ]
}
```
- **Best for**: CI/CD integration with GitHub Advanced Security, Azure DevOps, or other SARIF consumers.
- **Rendering**: `aibom scan --format sarif --output aibom-report.sarif` (add `--markdown-output aibom-report.md` to ship a human-readable copy from the same invocation).

### CycloneDX (AI-BOM aligned)
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {
      "type": "library",
      "name": "urllib3",
      "version": "1.26.18",
      "licenses": [{"license": {"id": "MIT"}}],
      "properties": [
        {"name": "aibom:issues", "value": "LOOSE_PIN"},
        {"name": "aibom:risk_score", "value": "82"}
      ]
    },
    {
      "type": "application",
      "name": "gpt2",
      "properties": [
        {"name": "aibom:source", "value": "huggingface"},
        {"name": "aibom:license", "value": "mit"},
        {"name": "aibom:issues", "value": "STALE_MODEL"}
      ]
    }
  ]
}
```
- **Best for**: downstream SBOM workflows, policy engines, and procurement reviews.
- **Rendering**: `aibom scan --format cyclonedx --sbom-output aibom-cyclonedx.json` (or `--format spdx`).

## Provenance attestation (machine-readable)
To capture hashes, git commit SHAs, and optional signatures, emit a provenance attestation alongside the report:

```bash
aibom scan --format json --output aibom-report.json --attestation-output aibom-attestation.json
```

The attestation JSON includes input/output hashes and the resolved git commit, making it easy to integrate with SLSA or in-toto workflows.

## Runtime tracing
Use the built-in runtime tracer to observe model loads or imports that static scanning can miss:

```bash
aibom trace scripts/run_inference.py --output aibom-runtime-trace.json
aibom scan --runtime-trace aibom-runtime-trace.json --format json --output aibom-report.json
```

## Choosing the right format
- Start with **JSON** for automation and diffing.
- Add **SARIF** when you want findings to surface directly in code hosting platforms.
- Emit **CycloneDX/SPDX** when handing SBOMs to supply chain or compliance teams.
