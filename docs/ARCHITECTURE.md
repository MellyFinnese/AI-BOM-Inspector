# AI-BOM Inspector Architecture

AI-BOM Inspector is a deterministic AI supply-chain risk engine. Its core job is to turn AI project inputs into an explainable security decision that can be enforced in CI.

## Core flow

```text
AI project
  |
  +--> SBOM / manifests / model metadata / artifacts
  |
  v
Discovery + parsing
  |
  v
Normalization
  |
  +--> components
  +--> models
  +--> applications
  +--> provenance metadata
  |
  v
Evidence + relationship context
  |
  +--> dependency relationships
  +--> model lineage
  +--> artifact evidence
  +--> vulnerability context
  +--> application / owner impact
  |
  v
Deterministic risk engine
  |
  +--> severity / risk factors
  +--> scoring explanation
  +--> temporal / organizational context
  |
  v
Policy engine
  |
  +--> allow
  +--> warn
  +--> block
  |
  v
Reporting + enforcement
  |
  +--> JSON / Markdown / HTML
  +--> CycloneDX / SPDX
  +--> SARIF / CI outputs
  +--> evidence packs / attestations
```

## Five layers

### 1. Discovery

Find dependency manifests, SBOMs, model metadata, model references, and model artifacts. Input is treated as untrusted.

### 2. Normalization

Convert heterogeneous inputs into typed internal representations. The goal is to avoid making downstream risk logic depend on the quirks of a specific input format.

### 3. Evidence and relationship context

Attach concrete observations to components and models, then build relationship context used for impact and explanation. The graph/context layer provides context; it is not the authoritative risk score.

### 4. Risk and policy

The deterministic risk engine calculates the security result from normalized findings and configured scoring settings. The policy engine converts that result and its evidence into an enforceable decision.

### 5. Reporting and enforcement

Expose the same underlying decision through human-readable reports, machine-readable formats, CI outputs, and evidence artifacts.

## Security boundaries

The important trust boundary is:

```text
Untrusted project data
        |
        v
Parsing / validation
        |
        v
Normalized security objects
        |
        v
Risk + policy decision
        |
        v
Evidence / enforcement outputs
```

Security-sensitive assumptions should be explicit:

- oversized inputs must be rejected before being fully loaded when a limit applies
- malformed input must fail in a controlled way
- missing data must not silently become stronger evidence
- canonical component identity should be preferred over ambiguous name-only matching
- trust roots require an external anchor when authenticating an untrusted trust-root file
- integrity digests must not be represented as cryptographic signatures
- policy failures must fail closed rather than disappearing through exceptions

## Graph boundary

Graph reasoning is most useful for relationship questions such as:

```text
vulnerability
   -> package
   -> AI framework
   -> model
   -> application
   -> owner
```

This supports blast-radius analysis, evidence traversal, and attack-path reasoning. A graph database such as Memgraph is optional architecture, not a requirement of the deterministic core.

## Core versus experimental

| Capability | Status |
| --- | --- |
| Deterministic risk engine | Core |
| Policy enforcement | Core |
| SBOM / manifest parsing | Core |
| Model and artifact analysis | Core |
| Graph-based impact context | Core |
| Golden vulnerable-AI demo | Core proof path |
| Adversarial regression coverage | Core security practice |
| CycloneDX / SPDX reporting | Core |
| GitHub / CI integration | Core integration |
| Memgraph adapter | Optional / experimental graph backend |
| Sigstore signing | Requires signing/provisioning; unsigned status is explicit when unavailable |
| Enterprise control plane | Roadmap / deployment architecture |

## Design principle

The system should answer four questions deterministically:

1. What AI assets exist?
2. What evidence indicates risk?
3. How does that risk propagate through the system?
4. Should policy allow, warn, or block the change?
