# AI-BOM Inspector

![AI-BOM Inspector CI](https://img.shields.io/badge/AI--BOM%20Inspector-Scan%20your%20AI%20stack%20in%20CI-blue)

**Deterministic AI supply-chain risk and impact analysis.**

AI-BOM Inspector analyzes dependencies, SBOMs, AI models, metadata, artifacts, and source code, then turns the resulting evidence into deterministic risk, relationship context, behavioral drift, impact paths, policy decisions, and CI-friendly reports.

The core design is **offline-first, deterministic, explainable, evidence-backed, resource-bounded, and enforceable**.

## Validation snapshot

The project maintains a regression suite, labeled detector benchmarks, adversarial coverage, cross-platform CI, fuzzing infrastructure, and scale-runtime checks. Published benchmark numbers are measured from the repository's benchmark corpus; capacity claims for large artifacts should be measured on target production hardware before being presented as guarantees.

The labeled JavaScript/TypeScript benchmark currently reports:

```text
30 benchmark cases
Precision: 93.94%
Recall:    95.38%
F1:        94.66%
```

The benchmark contains positive, clean-negative, and adversarial-negative cases. The quality gate remains **precision, recall, and F1 >= 0.90**.

## Project identity

This repository is the **canonical home for the AI-BOM Inspector implementation maintained by MellyFinnese**.

The project has evolved from AI supply-chain inventory and deterministic risk analysis into a broader impact-analysis workflow covering AI asset identity, provenance, JavaScript/TypeScript semantics, behavioral drift, attack-path reasoning, blast radius, graph-backed investigation, and production hardening.

The repository is the source of truth for the architecture, implementation, benchmarks, security validation, and release history described here.

## Stabilization milestone

**0.2.0 — Graph + Application Security Stabilization**

The current milestone consolidates the project around one product thesis:

> **Discover the AI stack, establish evidence and provenance, reason about relationships and reachable impact, and enforce deterministic policy decisions in CI.**

See [`docs/MILESTONE_2026_08.md`](docs/MILESTONE_2026_08.md) and [`CHANGELOG.md`](CHANGELOG.md) for the stabilized scope.

## Production hardening

The core/runtime hardening work now includes:

- streaming SHA-256 hashing for multi-gigabyte artifacts
- bounded artifact-size, item-count, worker-count, chunk-size, and timeout limits
- concurrent artifact scanning with deterministic output ordering
- crash-safe, `fsync`-backed checkpoints with atomic replacement
- incremental checkpoint reuse for unchanged artifacts
- optional full rehash verification of cached artifacts
- CPU / wall-time / RSS profiling where supported by the host
- disk-backed relationship storage for large relationship sets
- deterministic risk explanations and collision-resistant evidence graph IDs
- cryptographic provenance signing / verification primitives
- hash-chained audit logs and tamper verification
- cross-platform Python/Rust CI
- optional fuzzing and reproducible scale-benchmark infrastructure

Example bounded artifact scan:

```bash
aibom artifact-scan path/to/model.safetensors --workers 8 --max-bytes 17179869184 --checkpoint-dir .aibom-checkpoints
```

Incremental mode:

```bash
aibom artifact-scan path/to/model.safetensors --checkpoint-dir .aibom-checkpoints --incremental
```

High-assurance cached verification:

```bash
aibom artifact-scan path/to/model.safetensors --checkpoint-dir .aibom-checkpoints --incremental --rehash-cached
```

Runtime profiling:

```bash
aibom runtime-profile path/to/model.safetensors --workers 8
```

## Enterprise security

The repository now contains reusable enterprise-security primitives. The stabilized implementation includes:

```text
OIDC / SAML SSO
        ↓
SCIM lifecycle
        ↓
MFA enforcement
        ↓
RBAC + tenant isolation
        ↓
Short-lived credential policy
        ↓
Vault / KMS adapters
        ↓
Network ingress / egress controls
        ↓
Audit export + retention
```

The enterprise work covers:

- OIDC discovery, PKCE helpers, JWKS-backed JWT verification, issuer/audience/expiry/`nbf` and scope enforcement
- SAML signed assertion/message validation and HTTPS ACS requirements
- SCIM provisioning, disable/delete lifecycle, tenant association, and serialization
- TOTP MFA and recent-authentication enforcement, with optional phishing-resistant admin MFA policy
- RBAC roles and explicit permission checks
- tenant/workspace isolation primitives
- Vault KV read/rotation and AWS KMS data-key adapters
- credential TTL/rotation policy
- ingress CIDR and egress host/port policy
- blocking of loopback, link-local, private and reserved destinations
- bounded audit export, gzip support, and time-based retention/purge

Provider accounts, certificates, client credentials, IdP configuration, Vault/KMS permissions, and deployment infrastructure remain external configuration. The project intentionally does not pretend that a library primitive is equivalent to a deployed enterprise control plane.

## The core flow

```text
AI project
   |
   +--> SBOM / manifests / model metadata / artifacts / source code
   |
   v
Discovery + parsing
   |
   v
Normalization + identity
   |
   v
Evidence + relationship context
   |
   +--> JS/TS semantic analysis
   |        |
   |        v
   |    Behavioral drift
   |        |
   |        v
   |    Impact / attack paths
   |
   v
Deterministic risk engine
   |
   v
Policy + enterprise controls
   |
   v
Report / CI decision / evidence pack / graph export
```

### Architectural boundary

```text
                    Relationship + impact context
                                 |
SBOM / Models / Code -> Evidence Graph -> Impact Paths
                         |              |
                         v              v
                  Deterministic Risk -> Policy -> Enforcement
                         ^                    |
                         |                    v
                  scoring source of truth   audit
```

The graph/context layer provides identity, traversal, impact, behavioral change, and explanation. **The deterministic risk engine remains the scoring source of truth.** Memgraph and other graph databases are optional backends rather than requirements of the core engine.

## Impact analysis

The project treats behavioral change as a graph problem rather than only a line-diff problem.

A semantic JavaScript/TypeScript scan can represent relationships such as:

```text
HTTP / CLI / env / retrieval input
              |
              v
           prompt
              |
              v
            agent
              |
              v
             tool
              |
              v
       privileged operation
```

The formal `AttackPath` model records stable path identity, source and target nodes, ordered relationships, severity, and supporting evidence.

A behavioral diff can therefore answer:

> **Did this change create a new reachable impact path?**

That result can feed CLI output, CI policy, graph export, AI-BOM context, and optional graph backends.

## AI supply-chain analysis

The core engine covers:

- Python, JavaScript/TypeScript, Go, and Java manifests
- CycloneDX and SPDX SBOM ingestion
- AI model metadata and reference discovery
- dependency pinning and version posture
- model freshness and provenance signals
- license and governance analysis
- local and optional remote advisory enrichment
- model artifact hashing and integrity checks
- Safetensors inspection
- pickle/global analysis
- policy and trust enforcement

## JavaScript / TypeScript analysis

- offline static AI-usage discovery
- provider and model-call detection
- Agent and tool relationships
- prompt and trust-boundary analysis
- HTTP, CLI, environment, and retrieval sources
- alias-aware provider and agent resolution
- import/export relationship indexing
- bounded variable-level flow relationships
- cross-file relationship context
- behavioral drift between baseline and candidate scans

The JS/TS layer is intentionally conservative. It does not claim complete JavaScript data-flow, framework semantics, or exploitability.

## Risk, governance, and evidence

- deterministic risk scoring
- score explanations and risk breakdowns
- organizational context such as criticality and data sensitivity
- policy-as-code controls
- CI blocking / warning decisions
- report diffing
- evidence packs and attestations
- provenance verification
- hash-chained audit records
- enterprise access and network-policy primitives

## Graph and impact reasoning

The graph/context model supports:

- blast-radius analysis
- evidence traversal
- behavioral drift
- attack / impact paths
- relationship diffing
- backend-neutral graph export
- downstream investigation in optional graph backends

For code-level reasoning:

```text
source -> prompt -> agent -> tool -> privileged operation
```

## CLI

Run JavaScript/TypeScript analysis:

```bash
aibom js-scan path/to/project
```

Compare baseline and candidate behavior:

```bash
aibom behavior-diff baseline/ candidate/
```

Enumerate impact paths:

```bash
aibom attack-paths path/to/project
```

Export graph context:

```bash
aibom graph-export path/to/project --output graph.json
```

Run the benchmark:

```bash
aibom benchmark benchmarks/javascript/manifest.json
```

Run a bounded artifact scan:

```bash
aibom artifact-scan path/to/model.safetensors --workers 8 --max-bytes 17179869184
```

Profile the runtime:

```bash
aibom runtime-profile path/to/model.safetensors --workers 8
```

Run the full test suite:

```bash
pytest
```

## Memgraph

Memgraph is an optional investigation backend. The exported graph is backend-neutral.

Example query shape:

```cypher
MATCH p = (source)-[:EVIDENCE_PATH*1..8]->(sink)
WHERE source.kind = "input"
  AND sink.kind = "privileged-operation"
RETURN p;
```

The architecture deliberately keeps graph traversal separate from authoritative risk scoring.

## Benchmarking and security validation

The benchmark reports:

- overall precision / recall / F1
- per-detector metrics
- per-category metrics
- per-case false positives and false negatives
- adversarial regression coverage

Current detector-corpus result:

```text
Cases:     30
Precision: 93.94%
Recall:    95.38%
F1:        94.66%
```

Independent external repository validation is documented in [`docs/EXTERNAL_VALIDATION.md`](docs/EXTERNAL_VALIDATION.md). The current external validation target includes `d01ki/AIBOM-Inspector`, scanned offline and in safe mode to evaluate evidence-context and production-relevance classification.

For production capacity claims, benchmark on representative hardware and record:

```text
artifact / component / relationship counts
CPU + cores
RAM
storage class
Python + Rust versions
concurrency
incremental / full-scan mode
elapsed time
peak RSS
success / failure rate
```

The repository deliberately avoids publishing synthetic throughput claims as if they were measured production results.

## Security invariants

The project explicitly distinguishes:

- **integrity digest** from **cryptographic signature**
- **self-consistent trust root** from **externally trusted root**
- **missing evidence** from **positive evidence**
- **canonical identity** from **name-only matching**
- **controlled policy failure** from **silent exceptions**
- **changed relationships** from **newly reachable impact paths**
- **security primitives** from **deployed enterprise infrastructure**

These distinctions matter because the scanner itself is a security boundary.

## Core vs enterprise

| Capability | Status |
| --- | --- |
| Deterministic risk engine | **Core** |
| Policy enforcement | **Core** |
| SBOM / manifest parsing | **Core** |
| Model and artifact analysis | **Core** |
| AI asset identity / lineage | **Core** |
| Graph-based impact context | **Core** |
| JavaScript/TypeScript semantic analysis | **Core capability; conservative semantics** |
| Behavioral drift | **Core capability** |
| Formal impact / attack paths | **Core capability** |
| Production artifact runtime controls | **Core** |
| Incremental + crash-safe scanning | **Core** |
| Provenance signing / verification primitives | **Core capability** |
| Hash-chained audit log | **Core capability** |
| RBAC / tenant isolation primitives | **Enterprise capability** |
| OIDC / SAML SSO primitives | **Enterprise capability** |
| SCIM provisioning | **Enterprise capability** |
| MFA policy / verification | **Enterprise capability** |
| Vault / KMS adapters | **Enterprise capability** |
| Credential rotation / TTL policy | **Enterprise capability** |
| Network ingress / egress policy | **Enterprise capability** |
| Audit export / retention | **Enterprise capability** |
| CycloneDX / SPDX reporting | **Core** |
| GitHub / CI integration | **Core integration** |
| Backend-neutral graph export | **Core integration** |
| Memgraph adapter | **Optional / experimental** |
| Kubernetes / HA service plane | **Deployment roadmap** |
| Third-party penetration testing / certification | **External validation** |

## Further reading

- [Architecture](docs/ARCHITECTURE.md)
- [Security validation](docs/SECURITY_VALIDATION.md)
- [Production readiness](docs/PRODUCTION_READINESS.md)
- [2026-08 stabilization milestone](docs/MILESTONE_2026_08.md)
- [Independent external validation](docs/EXTERNAL_VALIDATION.md)
- [Policy](docs/POLICY.md)
- [Scoring](docs/SCORING.md)
- [Enterprise Trust Baseline](docs/ENTERPRISE_TRUST_BASELINE.md)
- [Policy Cookbook](docs/POLICY_COOKBOOK.md)
- [AI Supply Chain Threat Model](docs/AI_SUPPLY_CHAIN_THREAT_MODEL.md)

## Enterprise hardening

Enterprise identity, secrets, network, MFA, and audit controls are included in the stabilized implementation from [PR #132](https://github.com/MellyFinnese/AI-BOM-Inspector/pull/132). Deployment-specific provider configuration and infrastructure remain external concerns.
