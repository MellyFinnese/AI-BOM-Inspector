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

## Trust root signing + verification
To own the trust root for attestation signing, generate a local trust root and use it to sign reports:

```bash
aibom trust-root --output aibom-trust-root.json
aibom scan --format json --output aibom-report.json --attestation-output aibom-attestation.json --trust-root aibom-trust-root.json
aibom verify-attestation --attestation aibom-attestation.json --trust-root aibom-trust-root.json
aibom verify-trust-root --trust-root aibom-trust-root.json
```

## Runtime hash verification
Validate report integrity at consumption time using the SHA256 sidecar or attestation metadata:

```bash
aibom verify-report --report aibom-report.json --sha256 aibom-report.json.sha256
aibom verify-report --report aibom-report.json --attestation aibom-attestation.json
```

## Audit logs + evidence export
Record tamper-evident audit logs and export compliance evidence with framework mappings:

```bash
aibom scan --format json --output aibom-report.json --audit-log aibom-audit.jsonl --audit-actor \"ci@acme\"
aibom verify-audit-log --audit-log aibom-audit.jsonl
aibom export-evidence --report aibom-report.json --output aibom-evidence.json
```

## Runtime tracing
Use the built-in runtime tracer to observe model loads or imports that static scanning can miss:

```bash
aibom trace scripts/run_inference.py --output aibom-runtime-trace.json
aibom scan --runtime-trace aibom-runtime-trace.json --format json --output aibom-report.json
```

## Customer feedback workflow
Capture structured customer feedback to feed roadmap and governance workflows:

```bash
aibom feedback --summary "Need SOC 2 mapping detail" --category governance --priority high --organization "Acme AI" --workflow-stage audit
aibom feedback-metrics --input aibom-feedback.json --output aibom-feedback-metrics.json
```

## Choosing the right format
- Start with **JSON** for automation and diffing.
- Add **SARIF** when you want findings to surface directly in code hosting platforms.
- Emit **CycloneDX/SPDX** when handing SBOMs to supply chain or compliance teams.
