# Threat Modeling

This document complements the AI supply chain threat taxonomy with a system-level threat model for AI-BOM Inspector. It is intended as a living artifact to guide architecture reviews, security testing, and roadmap prioritization.

## Scope

**In scope**
- Control Plane API + services
- Policy Engine
- Evidence Store + data persistence
- CLI/CI ingestion clients
- Identity provider integrations
- Object storage + secrets management

**Out of scope (for now)**
- Third-party model registries and external package registries
- Customer-specific runtime model serving stacks

## System components

| Component | Description |
| --- | --- |
| CLI / CI Integrations | Emits signed AI-BOM artifacts and Control Plane bundles. |
| API Layer / Control Plane | REST/gRPC surface for tenancy, assets, policies, evidence, and audit. |
| Policy Engine | Evaluates AI-BOM + policies and produces decisions. |
| Evidence Store | Append-only storage for decision bundles and audit artifacts. |
| Database | Multi-tenant metadata store for orgs, projects, policies, assets. |
| Object Storage | Storage for large artifacts, evidence bundles, and attachments. |
| Identity Provider (OIDC) | Authentication + RBAC integration. |
| Secrets/KMS | Keys for signing, encryption, and credential storage. |

## Trust boundaries

1. **Client boundary**: CI/CD systems and CLI clients interact with the Control Plane API over the public network.
2. **Service boundary**: Control Plane ↔ Policy Engine ↔ Evidence Store communication (mTLS + service identity).
3. **Data boundary**: Control Plane services ↔ Database (row-level or physical isolation by tenant).
4. **Artifact boundary**: Control Plane services ↔ Object Storage (signed bundle ingestion and immutable retention).
5. **Identity boundary**: Control Plane services ↔ OIDC provider (token issuance and role claims).
6. **Key boundary**: Control Plane services ↔ KMS/Vault (signing + encryption keys).

## STRIDE analysis per component

The matrix below highlights representative threats per component. Items are prioritized for mitigation when they intersect with evidence integrity, tenant isolation, and auditability.

### CLI / CI Integrations

| STRIDE | Threat | Primary mitigations |
| --- | --- | --- |
| Spoofing | Fake CI agent submits bundle as trusted org/project. | OIDC tokens, signed bundles, per-tenant API keys. |
| Tampering | Bundle modified in transit. | TLS, bundle hashing, signature verification. |
| Repudiation | CI denies submission of bundle. | Immutable evidence records, audit logging. |
| Information disclosure | Sensitive metadata in CI logs. | Redaction guidelines, minimal payloads, optional encryption. |
| Denial of service | Flooding API with large bundles. | Rate limits, size limits, async ingestion. |
| Elevation of privilege | CI token used across tenants. | Scoped tokens, tenant-bound claims, RBAC. |

### API Layer / Control Plane

| STRIDE | Threat | Primary mitigations |
| --- | --- | --- |
| Spoofing | Stolen bearer token re-used. | Short-lived tokens, MFA, anomaly detection. |
| Tampering | Policy definitions altered without approval. | RBAC + approvals, signed policy versions. |
| Repudiation | Users deny policy changes. | Append-only audit logs, immutable evidence chains. |
| Information disclosure | Cross-tenant data leakage. | Row-level security, tenant-scoped queries, encryption. |
| Denial of service | API abuse, heavy query load. | Rate limiting, caching, request validation. |
| Elevation of privilege | Privilege escalation via mis-scoped roles. | Least-privilege roles, policy reviews, regression tests. |

### Policy Engine

| STRIDE | Threat | Primary mitigations |
| --- | --- | --- |
| Spoofing | Untrusted service submits evaluation results. | mTLS, service identity, signed responses. |
| Tampering | Policy evaluation rules changed. | Policy versioning, checksum validation. |
| Repudiation | Missing proof of evaluation decision. | Decision hashes, stored evidence bundle. |
| Information disclosure | Policy results expose sensitive model info. | Output minimization, redaction fields. |
| Denial of service | Heavy policy computations block pipeline. | Horizontal scaling, per-policy limits. |
| Elevation of privilege | Policy engine accepts unauthorized overrides. | Explicit override workflow, RBAC approval checks. |

### Evidence Store

| STRIDE | Threat | Primary mitigations |
| --- | --- | --- |
| Spoofing | Untrusted evidence records injected. | Signed bundles, ingest authentication. |
| Tampering | Evidence records modified or deleted. | WORM storage, append-only logs, hash chaining. |
| Repudiation | Deletion or alteration denied. | Immutable storage plus audit trails. |
| Information disclosure | Unauthorized access to evidence. | Tenant-scoped access, encryption at rest. |
| Denial of service | Storage exhaustion. | Retention policies, quotas, archival. |
| Elevation of privilege | Evidence retrieval bypasses RBAC. | RBAC enforcement, token scopes. |

### Database

| STRIDE | Threat | Primary mitigations |
| --- | --- | --- |
| Spoofing | Unauthorized DB connections. | Network ACLs, credential rotation. |
| Tampering | Direct data modification. | Least-privilege DB roles, audit logging. |
| Repudiation | Data changes without trace. | DB audit logs, immutable evidence references. |
| Information disclosure | Cross-tenant leakage. | Row-level security, encryption, per-tenant keys. |
| Denial of service | Query overload. | Query limits, connection pooling. |
| Elevation of privilege | Privilege escalation via SQL injection. | Input validation, parameterized queries. |

### Object Storage

| STRIDE | Threat | Primary mitigations |
| --- | --- | --- |
| Spoofing | Untrusted actor writes bundles. | Signed URLs, scoped credentials. |
| Tampering | Artifacts modified after upload. | Object lock/WORM, checksum validation. |
| Repudiation | Uploads denied or missing logs. | Storage access logs, immutable bucket policies. |
| Information disclosure | Unauthorized access to artifacts. | Private buckets, encryption, expiring URLs. |
| Denial of service | Storage throttling. | Quotas, tiered storage, caching. |
| Elevation of privilege | Misconfigured bucket policies. | Policy reviews, config-as-code guardrails. |

### Identity Provider (OIDC)

| STRIDE | Threat | Primary mitigations |
| --- | --- | --- |
| Spoofing | Compromised IdP tokens. | MFA, conditional access, token validation. |
| Tampering | Claims modified in transit. | JWT signature validation. |
| Repudiation | Auth events denied. | Centralized auth logs. |
| Information disclosure | Claims reveal sensitive info. | Minimize claims, least-privilege. |
| Denial of service | IdP outage. | Fallback sessions, cached tokens. |
| Elevation of privilege | Role mapping misconfiguration. | Role mapping validation, RBAC tests. |

### Secrets/KMS

| STRIDE | Threat | Primary mitigations |
| --- | --- | --- |
| Spoofing | Unauthorized key usage. | mTLS, IAM policies, key usage logs. |
| Tampering | Key material altered. | Managed KMS, rotation, HSM-backed keys. |
| Repudiation | Key usage denied. | KMS audit logs. |
| Information disclosure | Keys leaked via env/logs. | Secret scanning, vault injection, redaction. |
| Denial of service | KMS outage. | Key caching, fail-safe policies. |
| Elevation of privilege | Mis-scoped key permissions. | Least-privilege policies, periodic reviews. |

## Roadmap threats to revisit

- Runtime signal ingestion (new trust boundary: model runtime telemetry).
- External attestations (supply chain signature verification at scale).
- Multi-tenant analytics dashboards (aggregate query isolation).

## Related documentation

- AI supply chain threat taxonomy: `docs/AI_SUPPLY_CHAIN_THREAT_MODEL.md`.
- Deployment architecture: `docs/DEPLOYMENT_REFERENCE.md`.
- Control Plane API surface: `docs/ENTERPRISE_CONTROL_PLANE.md`.
