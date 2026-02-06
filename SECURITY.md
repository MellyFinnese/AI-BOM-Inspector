# Security Policy

- **Reporting:** Email security@aibom.dev with details. Include reproduction steps, affected versions, and any available mitigations.
- **Response:** Maintainers acknowledge within 3 business days and coordinate a fix or disclosure timeline.
- **Scope:** Vulnerabilities in CLI scanning, report generation, or dependency handling. For third-party packages, please report upstream when appropriate.

## Security posture

- **Supply-chain integrity:** AI-BOM reports can be signed with SHA256 hashes and attached to attestations for integrity validation.
- **Tamper evidence:** Audit logs use hash chaining to detect log rewrites or deletions.
- **Least privilege:** Policy approvals and exception workflows are designed to separate author and approver roles.
- **Tenant isolation:** Control plane access is scoped to tenant-bound identifiers on every API request.
- **Defense in depth:** Policy evaluation runs in isolated workers and emits structured evidence for downstream GRC tooling.
