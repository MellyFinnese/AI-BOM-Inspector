# Production-readiness hardening

This document distinguishes implemented core controls from controls that still require deployment operations or a third-party provider account.

## Implemented in the core runtime

- Streaming SHA-256 hashing for arbitrarily large artifacts.
- Bounded artifact size, item count, worker count, chunk size, and scan timeout controls.
- Concurrent artifact scanning with deterministic path ordering.
- Atomic, fsync-backed checkpoints for crash recovery.
- Incremental checkpoints keyed by canonical path + file size + mtime, with optional full rehash verification.
- Runtime profiling with elapsed time, CPU time, peak RSS where the host exposes it, Python version, and platform.
- Disk-backed SQLite relationship storage with WAL, indexed source/target traversal, batched inserts, and bounded shortest-path queries.
- Deterministic score explanations and collision-resistant evidence graph node IDs.
- Ed25519 signing/verification of canonical provenance payloads.
- Hash-chained audit logs with verification support.
- Cross-platform Python CI on 3.10, 3.11, and 3.12 across Ubuntu, macOS, and Windows.
- Optional Atheris fuzz target for model-manifest parsing.
- Reproducible scale benchmark harness and CI smoke benchmark.

## Enterprise identity and access

The enterprise security layer now includes concrete primitives for:

- RBAC roles: admin, security analyst, developer, auditor, read-only;
- tenant/workspace-aware authorization;
- OIDC discovery and cryptographic JWT verification through issuer JWKS;
- issuer, audience, expiry, not-before, required-scope, and MFA claim enforcement;
- SAML response validation through `python3-saml`, including signed-message/assertion validation and HTTPS ACS requirements;
- SCIM user provisioning, disable/deactivate, delete, and SCIM response serialization;
- TOTP verification plus recent-MFA and phishing-resistant admin MFA policy controls;
- Vault KV secret reads and rotations;
- AWS KMS data-key generation through the optional boto3 adapter;
- explicit short-lived credential TTL enforcement and rotation scheduling;
- ingress CIDR allow/deny controls and egress host/port/private-destination policy;
- audit export with size limits and optional gzip compression;
- audit retention/purge controls.

Install the enterprise dependencies with `pip install -e '.[enterprise]'`.

External provider credentials remain outside the codebase. Vault/KMS calls require the corresponding provider account and permissions. OIDC/SAML still require a configured identity provider, signing keys/certificates, and an HTTPS deployment endpoint.

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

## Enterprise operations still requiring deployment infrastructure

The repository does not claim that a CLI/library alone provides these controls. A production service still needs:

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

## Security verification expectations

Before treating this as an enterprise release:

1. run the full Python/Rust CI matrix;
2. install and test the enterprise extra;
3. run fuzzing with a time budget and retain crash artifacts;
4. execute scale benchmarks on representative hardware;
5. test checkpoint recovery by terminating scans mid-run;
6. verify OIDC signatures against a real IdP JWKS endpoint;
7. verify SAML assertions against a real IdP certificate;
8. test SCIM lifecycle events for every tenant;
9. test Vault/KMS access and rotation permissions;
10. verify network policies from an external deployment environment;
11. verify the audit chain after mutation attempts and exercise retention/export;
12. run an external penetration test against the deployed service layer;
13. publish measured capacity and operational limits.
