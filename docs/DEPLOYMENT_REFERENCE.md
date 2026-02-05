# Deployment Reference (SaaS + On-Prem)

AI-BOM Inspector enterprise services ship with SaaS and on-prem parity. This reference architecture documents the shared components and isolation model.

## Deployment models

### SaaS (multi-tenant)

- Shared Control Plane + Policy Engine
- Logical tenant isolation (`org_id`)
- Encrypted data at rest/in transit
- Centralized upgrades

### SaaS (single-tenant/dedicated)

- Dedicated VPC per customer
- Isolated database and object storage
- Optional customer-managed keys (KMS)

### On-prem / customer-managed

- No outbound connectivity required
- Customer-controlled data lifecycle
- Offline evidence retention

## Core infrastructure components

- **API Layer**: REST + gRPC services (Go/Rust)
- **Policy Engine**: stateless, horizontally scalable
- **Database**: PostgreSQL
- **Object storage**: S3-compatible (S3, GCS, MinIO)
- **Auth**: OIDC (Okta, Azure AD, Google)
- **Secrets**: Vault or Cloud KMS

## Data isolation model

- Tenant ID enforced at API and DB layer.
- Row-level security for multi-tenant SaaS.
- Physical isolation for dedicated SaaS/on-prem.

## Security controls

- mTLS between services
- Signed AI-BOM artifacts required for enforcement
- Immutable evidence storage
- Audit logs for all control-plane actions

## Operational expectations

- Horizontal scalability (stateless policy workers)
- Disaster recovery with automated backups
- Clear data residency and retention policies
