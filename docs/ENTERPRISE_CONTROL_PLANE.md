# Enterprise Control Plane

AI-BOM Inspector's enterprise platform turns inspection output into enforceable governance. The Control Plane is a standalone service that accepts signed AI-BOM artifacts, evaluates policies, and stores immutable evidence records.

## Goals

- Multi-tenant governance (orgs, projects, environments).
- Centralized policy definition + evaluation.
- Immutable, append-only evidence storage.
- CI/CD enforcement gates for releases.
- Role-based access control (RBAC) with OIDC integration.
- Enterprise SSO and identity federation.
- Control Plane UI for governance workflows.
- Policy packs to standardize guardrails across teams.
- Compliance reporting for audit readiness.

## High-level flow

1. **Inspector emits** a signed AI-BOM report.
2. **Control Plane registers** asset metadata.
3. **Policy Engine evaluates** the report against active policies.
4. **Evidence Store** persists the policy decision + artifacts.
5. **CI/CD gate** receives pass/fail and blocks on policy failure.

## API surface (MVP)

### Tenancy
- `POST /v1/organizations`
- `POST /v1/organizations/{org_id}/projects`
- `POST /v1/projects/{project_id}/environments`

### Asset registry
- `POST /v1/assets` (type, fingerprint, project_id)
- `GET /v1/assets/{asset_id}`

### Policies
- `POST /v1/policies`
- `GET /v1/policies?org_id=...`
- `POST /v1/policies/{policy_id}/activate`

### Evidence + audit
- `POST /v1/evidence` (Control Plane bundle ingestion)
- `GET /v1/evidence?asset_id=...`
- `GET /v1/audit` (RBAC-guarded)

### Identity, RBAC, and SSO (aspirational)
- `POST /v1/sso/providers`
- `GET /v1/sso/providers`
- `GET /v1/sso/providers/{provider_id}`
- `PATCH /v1/sso/providers/{provider_id}`
- `DELETE /v1/sso/providers/{provider_id}`
- `POST /v1/roles`
- `GET /v1/roles`
- `GET /v1/roles/{role_id}`
- `PATCH /v1/roles/{role_id}`
- `DELETE /v1/roles/{role_id}`
- `POST /v1/role-assignments`
- `GET /v1/role-assignments`
- `DELETE /v1/role-assignments/{assignment_id}`

### Policy packs (aspirational)
- `POST /v1/policy-packs`
- `GET /v1/policy-packs`
- `GET /v1/policy-packs/{pack_id}`
- `PATCH /v1/policy-packs/{pack_id}`
- `DELETE /v1/policy-packs/{pack_id}`

### Compliance reports (aspirational)
- `POST /v1/compliance/reports`
- `GET /v1/compliance/reports`
- `GET /v1/compliance/reports/{report_id}`
- `GET /v1/compliance/reports/{report_id}/download`

### Control Plane UI support (aspirational)
- `POST /v1/ui/session`
- `GET /v1/ui/overview`

## Control Plane UI (aspirational)

The Control Plane UI is the primary workflow surface for governance teams:

- Policy authoring, approvals, and version history.
- Evidence bundle review and exception management.
- Role assignments, SSO configuration, and access reviews.
- Compliance report generation (SOC 2 / ISO 27001 mapping).

## Data model (MVP)

| Table | Description |
| --- | --- |
| organizations | Multi-tenant root entity |
| projects | Team / workspace subdivision |
| assets | Models, datasets, pipelines |
| policies | JSON policy definitions |
| evidence_records | Immutable policy decisions + artifact URIs |

## Control Plane bundle (ingestion contract)

The CLI can emit a Control Plane bundle that the API can ingest verbatim:

- Schema: `schemas/control_plane_bundle.schema.json`
- Command: `aibom scan --control-plane-output ...`

The bundle includes:
- Tenant identifiers (org, project, environment).
- Asset fingerprint and type.
- AI-BOM JSON report + SHA256 hash.
- Policy decision payload (pass/fail + explanation).
- Optional attestation + signature references.
- Bundle hash for append-only chaining.

## Security hardening checklist

- **AuthZ on every Control Plane API** (token validation + tenant scoping).
- **Central RBAC enforcement middleware** to prevent per-endpoint drift.
- **OIDC + RBAC** at every API boundary.
- **Row-level tenant isolation** (or physical isolation for dedicated SaaS).
- **mTLS** between services (Control Plane ↔ Policy Engine ↔ Evidence Store).
- **WORM semantics** for evidence records (append-only, hash chained).
- **Signed AI-BOM artifacts** required for enforcement.
- **Audit logging** for logins, role changes, policy changes, and enforcement actions.

## CI/CD enforcement guidance

- Fail fast when `policy_decision = fail`.
- Store the full Control Plane bundle as an artifact.
- Require approvals for policy exceptions via the Control Plane API.

## Roadmap

- Policy versioning and rollback.
- Runtime signal ingestion for model usage metadata.
- OPA/Rego compatibility layer (future).
- Risk trend analytics dashboard.
- Policy packs marketplace + curated baselines.
- Compliance report exports (PDF/CSV/JSON) with evidence links.
- Phase 2 (strong signal): threat model refresh (UI + SSO), API fuzzing + schema validation, policy engine test harness.
- Phase 3 (enterprise polish): evidence artifacts for compliance, report integrity guarantees, tamper resistance on audit logs.
- Detailed hardening plan: `docs/HARDENING_PLAN.md`.
