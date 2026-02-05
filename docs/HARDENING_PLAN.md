# Control Plane Hardening Plan

This plan turns the security roadmap into actionable work items. It is intentionally aspirational and should be revisited after each delivery milestone.

## Objectives

- Enforce **authz on every Control Plane API** with centralized RBAC middleware.
- Strengthen **auditability** for login, role, policy, and enforcement actions.
- Establish **contract-driven validation** (OpenAPI/AsyncAPI + JSON schema) and fuzzing.
- Provide **tamper resistance** for audit logs and report integrity guarantees.
- Ship **evidence artifacts** that map controls to compliance reports.

## Phase 1 — Foundation (baseline security posture)

### Access control

- Central RBAC enforcement middleware applied to every API route.
- AuthZ checks for tenant scoping on all Control Plane APIs.
- Role assignments audited and visible in the Control Plane UI.

### Audit logging

- Log events for: login, role changes, policy changes, enforcement actions.
- Ensure audit logs include actor, timestamp, tenant, request ID, and outcome.

### Contracts and validation

- OpenAPI and JSON schema validation at ingestion boundaries.
- AsyncAPI contract validation for event payloads.

### Deliverables

- Middleware library + authz policy registry.
- Baseline audit event schema + storage strategy.
- Contract validation checks in CI.

## Phase 2 — Strong signal (security confidence)

### Threat model refresh

- Expand UI + SSO trust boundaries in `docs/THREAT_MODELING.md`.
- Reassess STRIDE mitigations for SSO broker dependencies and IdP outages.

### API fuzzing + schema validation

- Fuzz critical endpoints (`/v1/evidence`, `/v1/policies`, `/v1/assets`).
- Validate error handling against OpenAPI contracts.

### Policy engine test harness

- Deterministic fixtures for policy evaluations.
- Regression suite for policy pack behavior changes.

### Deliverables

- Fuzzing harness + negative test suites.
- Policy engine test harness with reproducible fixtures.
- Updated threat model report and sign-off checklist.

## Phase 3 — Enterprise polish (audit readiness)

### Evidence artifacts for compliance

- Evidence bundles mapped to SOC 2 / ISO 27001 control narratives.
- Compliance report exports with evidence links.

### Report integrity guarantees

- Hash-based integrity for compliance reports.
- Signed report bundles stored in WORM storage.

### Tamper resistance on audit logs

- Append-only, hash-chained audit log storage.
- Periodic integrity verification with alerts on mismatch.

### Deliverables

- Report signing workflow and verification tooling.
- Tamper-evident audit log pipeline.
- Compliance evidence registry for audit exports.

## Dependencies and owners (aspirational)

| Area | Dependencies | Primary owner |
| --- | --- | --- |
| AuthZ + RBAC | OIDC, role model, middleware | Platform Security |
| Audit logging | Evidence store, logging pipeline | Control Plane |
| Contract validation | OpenAPI/AsyncAPI specs, CI | Developer Experience |
| Fuzzing + harness | Test infra, fixtures | Security Engineering |
| Compliance evidence | Report generator, evidence store | GRC / Compliance |

## Success metrics

- 100% API coverage by RBAC middleware.
- Audit log coverage for all login, role, policy, and enforcement actions.
- Contract validation + fuzzing running in CI for critical endpoints.
- Tamper-evident audit log verification with zero integrity violations.
- Compliance reports generated with linked evidence artifacts.
