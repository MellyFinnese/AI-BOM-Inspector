# Enterprise roadmap (policy server, org + audit features)

This roadmap focuses on the enterprise-grade gaps called out in recent feedback: centralized policy governance, multi-org auditability, and executive-ready reporting. It is intentionally product-facing so it can anchor planning for a web UI, SaaS/on-prem control plane, and audit features.

## 1) Central policy server + org model (P0)
- **Policy API**: versioned policy bundles, immutable policy history, and rollbacks.
- **Multi-tenant orgs**: org → project → environment hierarchy with scoped policies.
- **Policy sync**: CLI/agents pull signed policies, cache locally, and record policy hashes in evidence bundles.
- **Audit logs**: signed policy changes with actor attribution and approval trails.

## 2) Evidence chain-of-custody (P0)
- **Centralized evidence store**: ingest signed reports, attestations, and audit logs.
- **Evidence timeline**: trace scan → policy → decision for any environment.
- **Retention + export**: per-org retention settings and export to GRC systems.

## 3) Executive UX + dashboards (P1)
- **Risk posture trends**: score history, CVE trend lines, and model risk deltas.
- **Org scorecards**: portfolio heatmaps across teams/projects.
- **Model metadata coverage**: lineage, training provenance, license ambiguity, and risk profile coverage KPIs.

## 4) Control plane web UI (P1)
- **Admin console**: org provisioning, project setup, and policy staging.
- **Audit console**: evidence explorer, chain-of-custody graph, and compliance exports.
- **Alerts**: policy drift, integrity failures, and CVE spikes.

## 5) SaaS + deployable backend (P1)
- **SaaS multi-tenant**: hosted control plane for centralized governance.
- **On-prem**: containerized deployment with isolated storage and private integrations.

## 6) Pluggable risk models (P2)
- **Weighted org-specific scoring**: customizable category weights (lineage, provenance, license ambiguity, model risk profiles).
- **Temporal risk inputs**: exploit maturity and active exploitation signals embedded in advisories.
- **Model metadata first**: emphasize AI-specific risk signals in executive reporting.
