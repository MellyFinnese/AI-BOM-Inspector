# Compliance Mapping (Aspirational)

This document maps AI-BOM Inspector capabilities to SOC 2 and ISO/IEC 27001 controls. It is aspirational and intended for roadmap alignment rather than audit evidence.

## Compliance reporting (aspirational)

- **Compliance reports** aggregate policy decisions, evidence bundles, and audit events into a mapped control narrative.
- **Policy packs** provide standardized baselines (SOC 2 / ISO 27001) for consistent enforcement across teams.

## SOC 2 (Trust Services Criteria)

| SOC 2 Criteria | Control intent | AI-BOM Inspector alignment (aspirational) |
| --- | --- | --- |
| CC1.2, CC1.3 | Governance, accountability | Policy approvals, immutable evidence for changes. |
| CC2.1 | Communication of responsibilities | Documented policy definitions + audit logs. |
| CC3.2 | Risk identification and assessment | Threat taxonomy + policy risk scoring. |
| CC4.1 | Monitoring controls | Continuous evidence ingestion + audit trails. |
| CC5.2 | Control activities | Policy engine enforcement + approvals. |
| CC6.1 | Logical access controls | RBAC + OIDC integration. |
| CC6.6 | Network security | mTLS between services, encrypted transport. |
| CC7.2 | Change management | Policy versioning + decision history. |
| CC7.3 | Incident response | Evidence bundle retention for investigations. |
| CC8.1 | System change tracking | Immutable evidence + audit logs. |
| CC9.2 | Vendor risk | Source attribution + registry allowlists. |

## ISO/IEC 27001:2022 (Annex A)

| ISO 27001 Control | Control intent | AI-BOM Inspector alignment (aspirational) |
| --- | --- | --- |
| A.5.1 | Policies for information security | Policy engine with explicit governance rules. |
| A.5.15 | Access control | RBAC + OIDC integration for Control Plane. |
| A.5.23 | Information security for use of cloud services | Deployment reference with isolation guidance. |
| A.5.28 | Evidence of compliance | Append-only evidence store and audit trails. |
| A.5.30 | ICT readiness for business continuity | Evidence retention + disaster recovery guidance. |
| A.8.8 | Management of technical vulnerabilities | CVE + advisory correlation in inspections. |
| A.8.9 | Configuration management | Policy and schema versioning. |
| A.8.10 | Information deletion | Retention policies and archive workflows. |
| A.8.11 | Data masking | Redaction guidance for outputs. |
| A.8.12 | Data leakage prevention | Policy enforcement for source and license controls. |
| A.8.20 | Network security | mTLS between services. |
| A.8.21 | Secure authentication | OIDC integration + token validation. |
| A.8.23 | Web filtering | Registry allowlists and provenance checks. |
| A.8.24 | Use of cryptography | Signed bundles, hashes, KMS guidance. |
| A.8.28 | Secure coding | Contract-driven APIs + schema validation. |

## Evidence sources (future)

- Policy decision logs and evidence bundles.
- Audit event exports.
- Schema validation reports for Control Plane bundles.
