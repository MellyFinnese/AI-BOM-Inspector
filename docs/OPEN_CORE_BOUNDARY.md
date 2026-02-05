# Open-Core Boundary

AI-BOM Inspector follows a clear open-core strategy:

> Developers inspect. Enterprises govern.

## Open Source (Apache 2.0)

Always free, community-focused capabilities:

- AI-BOM generation and static analysis
- Standards support (CycloneDX, SPDX)
- Local CLI usage
- Report generation (JSON, HTML, Markdown, SARIF)

## Enterprise (Commercial EULA)

Enterprise-only governance capabilities:

- Control Plane service (multi-tenant + RBAC)
- Policy enforcement gates for CI/CD
- Evidence & audit store (append-only)
- Centralized asset registry
- Enterprise policy packs + mapping

## Boundary enforcement

- **Network boundary**: enterprise features live in separate services.
- **No feature flags in OSS**: OSS remains standalone and complete.
- **Enterprise uses OSS outputs**: the Control Plane consumes signed AI-BOM artifacts.

## Packaging guidance

- Enterprise services ship as separate binaries/containers.
- OSS continues to compile/run without enterprise dependencies.
- Enterprise APIs are not reachable in OSS builds.

## Pricing levers (examples)

- Number of assets tracked
- Policy count
- Evidence retention period
- Deployment model (SaaS vs on-prem)
