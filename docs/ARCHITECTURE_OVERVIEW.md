# Architecture overview

## Executive summary
AI-BOM Inspector is composed of a scanning CLI, a policy engine, and a control plane that stores evidence for audits. The system produces signed, tamper-evident artifacts that let security and GRC teams trace every decision back to a specific scan and policy version.

## Core components

| Component | Responsibility | Primary artifacts |
| --- | --- | --- |
| Scanner CLI | Discover dependencies, models, and runtime traces; generate AI-BOM reports. | AI-BOM JSON/Markdown/HTML reports, runtime trace JSON. |
| Policy engine | Evaluate policy packs against AI-BOM reports and enforce CI/CD gates. | Policy evaluations, enforcement decisions, GitHub check payloads. |
| Evidence store | Persist append-only audit logs, signed reports, and compliance exports. | Evidence bundles, audit log JSONL, compliance exports. |
| Control plane | Multi-tenant governance APIs for policies, evidence, and audit review. | Policy definitions, role assignments, audit queries. |
| Control plane UI | Human-friendly governance dashboards for security and GRC users. | Audit log viewer, policy approvals, compliance reports. |

## Data flow (high level)
1. **Scan**: The CLI analyzes repositories and emits an AI-BOM report.
2. **Evaluate**: The policy engine scores the report, evaluates policy packs, and outputs a decision.
3. **Sign**: The report is hashed, signed, and packaged with policy evidence.
4. **Store**: Evidence bundles and audit log entries are appended to an immutable store.
5. **Review**: The control plane UI surfaces evidence, audit trails, and compliance exports.

## Trust model
- **Tamper evidence**: Audit logs use hash chaining; evidence bundles include report hashes.
- **Integrity verification**: Reports can be verified via SHA256 files or signed attestations.
- **Separation of duties**: Policy authors and approvers are tracked separately through approvals metadata.
- **Tenant isolation**: Control plane APIs enforce tenant-bound claims for all evidence access.

## Compliance artifacts
- **Evidence export**: JSON summary with framework mappings for SOC 2 / ISO 27001.
- **Audit trail export**: JSONL append-only log for audit review.
- **Compliance report**: Human-readable report with policy decisions and mapped controls.
