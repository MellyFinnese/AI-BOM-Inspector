# AI-BOM Inspector — Stabilization Milestone (2026-08)

This milestone freezes a coherent engineering snapshot after the project expanded from deterministic AI supply-chain inventory into AI asset provenance, graph-backed impact analysis, semantic application analysis, behavioral drift, policy enforcement, and production hardening.

## Milestone goals

1. Keep the deterministic risk engine as the scoring source of truth.
2. Make evidence provenance explicit and distinguish production evidence from tests, benchmarks, documentation, and examples.
3. Make graph context useful for lineage, blast radius, attack paths, and behavioral change without coupling the core scorer to a graph backend.
4. Maintain a reproducible JS/TS benchmark with precision, recall, and F1 gates at or above 0.90.
5. Validate behavior against independent external repositories and turn confirmed blind spots into regression coverage.
6. Keep enterprise capabilities clearly separated between reusable security primitives and deployed control-plane infrastructure.

## Current validation snapshot

- JavaScript/TypeScript benchmark: 30 cases
- Precision: 93.94%
- Recall: 95.38%
- F1: 94.66%
- Benchmark gate: precision, recall, and F1 >= 0.90
- Current full-suite snapshot: 152 passed, 1 skipped
- External validation corpus: `external-validation/`

The benchmark numbers are repository measurements. Capacity and deployment guarantees still require representative target-hardware validation.

## Stabilization checklist

### Repository consistency

- Package metadata points to the canonical `MellyFinnese/AI-BOM-Inspector` repository.
- README and milestone documentation distinguish implemented controls from roadmap and external-validation work.
- Enterprise features are described as security primitives unless deployed provider infrastructure exists.

### Security model

- Deterministic risk remains authoritative.
- Graph traversal provides relationship context and explanation.
- Evidence identity is explicit and contextual.
- Integrity digests are not represented as signatures.
- Trust roots require an external authenticity anchor when used to authenticate untrusted material.

### Independent validation

Each external repository should be recorded with:

- repository URL and commit/reference used
- scan mode and CLI command
- files/components discovered
- evidence-context distribution
- production-relevance distribution
- benchmark or regression findings
- limitations and false-positive/false-negative observations

External validation is evidence about observed behavior, not a claim of universal coverage.

## Recommended release framing

**AI-BOM Inspector 0.2.x — Graph + Application Security Stabilization**

The release headline should emphasize the system's stable security thesis:

> Discover the AI stack, establish evidence and provenance, reason about relationships and reachable impact, and enforce deterministic policy decisions in CI.

Feature depth should remain subordinate to that product story.
