# Enterprise trust baseline

These are the non-negotiable controls that make AI-BOM Inspector a go/no-go decision in enterprise procurement. They reinforce supply-chain integrity, minimize silent compromise, and establish a defensible trust root.

## 1) Provenance & signing (deal-maker)
- **Cosign-signed releases**: every release artifact is signed and verifiable in CI/CD (e.g., `cosign verify`).
- **Build attestations**: attach provenance data to release artifacts (builder identity, inputs/outputs, timestamps).
- **SLSA-aligned CI pipeline**: align build steps with SLSA requirements so downstream teams can reason about build integrity.
- **Reproducible builds**: deterministic builds that can be re-produced and verified by third parties.

## 2) Artifact integrity (anti-tamper)
- **Runtime hash verification**: verify report/attestation hashes at consumption time.
- **Signed plugins/extensions**: require plugin signatures before loading or execution.
- **Config + ruleset integrity checks**: validate policies and configuration files against known hashes/signatures before applying.

## 3) Dependency trust enforcement (core differentiation)
- **Signature verification on dependencies**: verify signatures for packages and model artifacts when available.
- **Trusted registry allowlists**: block dependencies outside approved registries.
- **Dependency confusion detection**: flag packages that could shadow internal names.
- **Lockfile checksum enforcement**: verify lockfile checksums to prevent stealthy changes.

## Operational outcomes
- **Procurement credibility**: trust signals (signatures + attestations) in every release.
- **CI/CD gating**: enforce verification before a build can ship.
- **Audit readiness**: evidence trails aligned with SLSA/in-toto workflows.
