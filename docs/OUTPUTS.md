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
- **Model lineage + hashes**: `models[].base_models`, `models[].fine_tuned_from`, `models[].training_sources`, and `models[].hashes` carry provenance and fingerprint signals for reputation checks.
- **Threat summary**: `threat_summary` links issue codes to the AI threat taxonomy (MITRE ATLAS / STRIDE) for executive-ready risk mapping.

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

## Control Plane bundle (enterprise ingestion)
Emit a Control Plane bundle to feed the enterprise policy engine and evidence store:

```bash
aibom scan --format json --output aibom-report.json \
  --control-plane-output aibom-control-plane.json \
  --control-plane-org 2c4f28c8-6f9b-4a3b-9a5d-1a7c2a8f7f91 \
  --control-plane-project 6e6c1d1c-4a1f-4b8e-9f8c-2e4f3f56a0f2 \
  --control-plane-environment prod \
  --control-plane-asset-type model \
  --control-plane-asset-fingerprint sha256:abc123
```

- **Best for**: enterprise governance workflows that need immutable evidence and policy decisions.
- **Schema**: `schemas/control_plane_bundle.schema.json` (Control Plane API ingestion contract).

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

### Sample evidence pack for buyers
For security review handoffs, see the sample artifacts in `docs/evidence-pack/`:

- `sample-compliance-report.json` — compliance summary with framework mappings.
- `sample-audit-log.jsonl` — hash-chained audit log entries ready for verification.
- `evidence-manifest.json` — generated manifest (from `--evidence-pack`) with file hashes and bundle chain hash.
- `evidence-manifest.sig.json` — optional signature (from `--sign-evidence --trust-root`) for non-repudiation.

These files are formatted as reference outputs for GRC, auditors, and security teams.

## IP protection outputs
Apply selective obfuscation and strip symbols from production binaries:

```bash
aibom ip-protect --obfuscate src/proprietary_logic.py --strip-symbols dist/agent.bin --output-dir ip-protection
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
