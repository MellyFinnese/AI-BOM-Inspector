# Security Policy

AI-BOM Inspector is security-focused software, so vulnerability reports are handled separately from normal feature requests and bug reports.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to **jordandesjarlais.2022@gmail.com**.

Include, where available:

- affected version or commit
- affected component or command
- reproduction steps or a proof of concept
- expected and observed behavior
- security impact
- relevant logs, traces, or sample inputs
- suggested mitigation, if known

Do not publish credentials, private data, or a working exploit in a public issue.

## Response expectations

Maintainers aim to acknowledge security reports within **3 business days** and will coordinate investigation, remediation, and an appropriate disclosure timeline.

## Scope

Security reports are particularly relevant to:

- CLI and artifact scanning
- dependency and SBOM handling
- model/artifact parsing
- report and evidence generation
- policy enforcement
- provenance and integrity mechanisms
- authentication, authorization, tenant isolation, and network-policy primitives
- audit logging and export

For vulnerabilities that clearly belong to a third-party dependency, report them upstream as appropriate and include the upstream issue or advisory reference when available.

## Security posture

The project is designed around explicit security boundaries:

- **Supply-chain integrity:** reports and attestations can carry integrity digests and cryptographic verification material.
- **Tamper evidence:** audit logs use hash chaining to detect unexpected rewrites or deletions.
- **Least privilege:** policy approvals and exception workflows are designed to separate author and approver responsibilities.
- **Tenant isolation:** control-plane access is scoped to tenant-bound identifiers.
- **Resource bounds:** artifact size, worker count, item count, chunk size, and time limits can constrain untrusted workloads.
- **Evidence-first decisions:** security findings are intended to remain traceable to concrete evidence rather than relying on unexplained scores.
- **Conservative analysis:** the project avoids claiming complete language semantics or exploitability where the implementation cannot establish them.

## Important limitations

Library primitives are not equivalent to a fully deployed enterprise control plane. Real deployments still require secure identity-provider configuration, secrets management, network controls, infrastructure hardening, monitoring, and operational procedures.

Likewise, benchmark performance and detection metrics should not be interpreted as guarantees for every production environment. Validate representative workloads and threat models before relying on the tool as a security control.
