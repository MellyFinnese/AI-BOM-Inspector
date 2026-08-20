# Changelog

## 0.2.0 — Graph + Application Security Stabilization

This milestone consolidates the AI-BOM Inspector architecture around deterministic risk, evidence-backed AI asset identity, graph/context reasoning, semantic JavaScript/TypeScript analysis, behavioral drift, attack paths, policy enforcement, and production hardening.

### Added

- AI asset identity and lineage for models, model versions, datasets, artifacts, training/fine-tuning runs, deployments, and evaluations.
- Deterministic evidence and relationship indexing for lineage, downstream/upstream traversal, and impact context.
- JavaScript/TypeScript semantic analysis for providers, model calls, agents, MCP, tools, prompt sinks, trust-boundary sources, and privileged operations.
- Behavioral drift and formal attack-path reasoning.
- Evidence-context classification for test, benchmark, documentation, example, implementation, and production references.
- Streaming artifact hashing, bounded concurrency, checkpoints, incremental reuse, and optional cached-artifact rehash verification.
- Provenance verification primitives, hash-chained audit records, and production hardening validation infrastructure.
- Enterprise security primitives covering OIDC/SAML, SCIM, MFA, RBAC/tenant isolation, Vault/KMS adapters, credential TTL/rotation, network policy, and audit export/retention.
- Backend-neutral graph export with optional Memgraph integration.

### Validation

- 30-case labeled JavaScript/TypeScript benchmark.
- Precision: 93.94%.
- Recall: 95.38%.
- F1: 94.66%.
- Quality gate: precision, recall, and F1 >= 0.90.
- Independent external repository validation documented in `docs/EXTERNAL_VALIDATION.md`.

### Security posture

The project explicitly distinguishes integrity digests from signatures, self-consistent trust roots from externally anchored trust roots, missing evidence from positive evidence, canonical identity from ambiguous name matching, and reusable security primitives from deployed enterprise infrastructure.

### Known roadmap / external validation

- Kubernetes / HA service-plane deployment.
- Third-party penetration testing and certification.
- Broader independent repository validation with representative production applications.

## Unreleased

- Future changes will be listed here after the 0.2.0 stabilization milestone.
