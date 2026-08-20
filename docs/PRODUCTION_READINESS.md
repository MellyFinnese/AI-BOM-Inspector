# Production-readiness hardening

This document defines the production hardening baseline for AI-BOM Inspector and distinguishes implemented controls from controls that require an external platform or enterprise identity provider.

## Implemented in the core runtime

- Streaming SHA-256 hashing for arbitrarily large artifacts.
- Bounded artifact size, item count, worker count, chunk size, and scan timeout controls.
- Concurrent artifact scanning with deterministic path ordering.
- Atomic, fsync-backed checkpoints for crash recovery.
- Incremental checkpoints keyed by canonical path + file size + mtime, with optional full rehash verification.
- Runtime profiling with elapsed time, CPU time, peak RSS where the host exposes it, Python version, and platform.
- Disk-backed SQLite relationship storage with WAL, indexed source/target traversal, batched inserts, and bounded shortest-path queries.
- Deterministic score explanations and collision-resistant evidence graph node IDs.
- Optional Ed25519 signing/verification of canonical provenance payloads.
- Hash-chained audit logs with verification support.
- Cross-platform Python CI on 3.10, 3.11, and 3.12 across Ubuntu, macOS, and Windows.
- Optional Atheris fuzz target for model-manifest parsing.
- Reproducible scale benchmark harness and CI smoke benchmark.

## CLI controls

`aibom artifact-scan` supports:

- `--workers` for bounded concurrency.
- `--timeout` for per-artifact execution budgets.
- `--max-bytes` for artifact limits.
- `--max-items` for batch limits.
- `--checkpoint-dir` for resumable scans.
- `--incremental` to reuse unchanged checkpoints without rehashing.
- `--rehash-cached` to require a full SHA-256 verification before reuse.

`aibom runtime-profile` emits a machine-readable performance profile.

## Benchmarking

For a real capacity claim, run the benchmark on the target production class of hardware. Do not publish synthetic or unmeasured numbers as fact.

Example:

```text
python benchmarks/scale_benchmark.py --artifacts 48000 --bytes-per-artifact 262144 --workers 32
```

For a multi-gigabyte single-artifact test, use `aibom artifact-scan` against a real model artifact and record the emitted SHA-256, elapsed time, and runtime profile. A credible published statement should include:

- artifact set size and component/relationship count;
- CPU model and core count;
- RAM;
- storage class;
- Python/Rust versions;
- concurrency;
- whether incremental mode was enabled;
- elapsed time;
- peak RSS;
- success/failure rate.

## Enterprise identity and access

`enterprise_security.py` provides the stable authorization boundary used by an eventual service layer:

- roles: admin, security analyst, developer, auditor, read-only;
- explicit permissions;
- tenant isolation checks;
- workspace identifiers;
- secret references that reject embedded raw credentials.

OIDC/SAML authentication, SCIM provisioning, MFA, Vault/KMS adapters, and network policy enforcement belong in the service/deployment layer. The core library deliberately fails closed when an external secret provider is referenced without an adapter instead of pretending a local implementation is equivalent to an enterprise identity system.

## Enterprise operations still requiring deployment infrastructure

The repository does not claim that a CLI alone provides these controls. They require an actual service architecture and operational environment:

- Kubernetes/Helm deployment;
- HA API and worker topology;
- durable job queue;
- multi-tenant persistent database;
- object storage and backup policy;
- Prometheus/OpenTelemetry integration;
- centralized logs and SIEM export;
- automated migrations and disaster recovery;
- measured SLO/SLA, RPO and RTO targets;
- third-party penetration testing and independent audit.

Those should be added only when the corresponding service interfaces exist, rather than creating deployment manifests that cannot execute real production workflows.

## Security verification expectations

Before treating this as an enterprise release:

1. run the full Python/Rust CI matrix;
2. run fuzzing with a time budget and retain crash artifacts;
3. execute scale benchmarks on representative hardware;
4. test checkpoint recovery by terminating scans mid-run;
5. verify attestation signatures and tamper detection;
6. verify the audit chain after mutation attempts;
7. run an external penetration test against the deployed service layer;
8. publish measured capacity and operational limits.
