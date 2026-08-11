# Optional Graph Architecture and Memgraph POC

## Repository audit summary

AI-BOM Inspector currently scans project manifests and model metadata, enriches dependencies/models with local or optional network intelligence, scores risk deterministically, evaluates policy, and renders reports/CI artifacts. The implemented flow is:

```text
Input / Parsers
  -> Normalization into DependencyInfo and ModelInfo
  -> Enrichment (OSV, model advisories, licenses, trust signals, stack discovery)
  -> Optional graph context for relationship lookup/explainability
  -> Default scoring model in the risk engine
  -> Policy engine and graph-policy guardrails
  -> Reports, attestations, evidence packs, SARIF/SBOM outputs
```

Implemented entities verified in source and tests include dependencies, dependency issues/findings, models, model issues/findings, licenses/license categories, model lineage fields, training source fields, stack-discovery graph nodes/edges, runtime traces, policies, policy violations, integrity findings, reports, evidence/export artifacts, audit logs, and deterministic score explanations.

Partially implemented or context-dependent entities include applications, owners, and production assets: organizational scoring context exists, and stack discovery can find tools/providers/models/env vars, but the current report model does not contain a first-class application/owner/deployment schema. The report ingester does not create application/owner relationships.

Existing graph-like functionality already existed before this POC: `policy_graph.py` provides `GraphNode`, `GraphEdge`, `GraphSnapshot`, and deterministic graph guardrail evaluation for stack-discovery policy. `scoring_models.py` also emits a lightweight score explanation graph. The new GraphStore does not replace either; it adds optional persistence/query context beneath the risk engine.

## Target component boundaries

```text
AI-BOM Inspector
├── Input / Parsers
├── Normalization
├── Enrichment
├── GraphStore
│     ├── In-Memory
│     └── Memgraph
├── Risk Engine
├── Policy Engine
├── Evidence / Integrity
└── Outputs
```

- **Input / Parsers** read requirements, package lockfiles, SBOMs, model JSON, runtime traces, and policies.
- **Normalization** produces `DependencyInfo`, `ModelInfo`, and `Report` objects.
- **Enrichment** attaches issues, CVE/advisory metadata, license categories, trust signals, stack discovery, and provenance metadata.
- **GraphStore** persists/query relationships already present in report data. It is optional and must fail closed without changing scan results.
- **Risk Engine** remains authoritative for deterministic scoring.
- **Policy Engine** evaluates policy-as-code and existing graph guardrails.
- **Evidence / Integrity** handles hashes, attestations, audit logs, trust roots, and evidence packs.
- **Outputs** render JSON, Markdown, HTML, SARIF, CycloneDX, SPDX, and control-plane bundles.

## Graph data model

The report ingester currently creates only relationships supported by existing report data:

- `Report -[:CONTAINS]-> Dependency`
- `Report -[:CONTAINS]-> Model`
- `Dependency -[:DECLARED_LICENSE]-> License`
- `Model -[:DECLARED_LICENSE]-> License`
- `Dependency -[:AFFECTED_BY]-> Vulnerability` when an issue contains a CVE/advisory identifier
- `Model -[:AFFECTED_BY]-> Vulnerability` when a model issue contains a CVE/advisory identifier
- `Model -[:DERIVED_FROM]-> Model` from `base_models` and `fine_tuned_from`
- `Model -[:TRAINED_ON]-> TrainingSource`
- `Finding -[:EVIDENCED_BY]-> Dependency|Model`

Relationships **not currently derived from report data**:

- `Model -[:USES_DEPENDENCY]-> Dependency` unless supplied by future/imported relationship evidence
- `Application -[:USES_MODEL]-> Model`
- `Application -[:USES_DEPENDENCY]-> Dependency`
- `Application -[:OWNED_BY]-> Owner`
- `Application -[:GOVERNED_BY]-> Policy`

When current scan data lacks direct model-to-dependency, application, owner, or deployment relationships, queries return empty evidence rather than fabricated links.

## Memgraph integration

`GraphStore` is a small protocol with an in-memory implementation and a Memgraph adapter. The Memgraph adapter uses the optional `neo4j` Python driver over Bolt and writes Cypher with parameterized values. Relationship types are allowlisted because Cypher cannot parameterize labels/types.

Implemented Memgraph read/query methods now query Memgraph directly rather than the in-memory mirror:

- `models_affected_by_vulnerability()`
- `models_depending_on_package()`
- `explain_finding()`
- `common_dependencies_for_findings()`

Environment variables:

- `AIBOM_MEMGRAPH_URI` defaults to `bolt://localhost:7687`
- `AIBOM_MEMGRAPH_USER` defaults to empty
- `AIBOM_MEMGRAPH_PASSWORD` defaults to empty

Local development and integration tests:

```bash
docker compose -f examples/memgraph/docker-compose.yml up -d
pip install '.[memgraph]'
AIBOM_RUN_MEMGRAPH_TESTS=1 pytest tests/test_memgraph_integration.py
PYTHONPATH=src python examples/memgraph/vulnerability_traversal.py
```

Example Cypher queries:

```cypher
MATCH (m:GraphEntity {label: 'Model'})-[:AFFECTED_BY]->(v:GraphEntity {id: 'Vulnerability:CVE-2026-0001'}) RETURN m;
MATCH (m:GraphEntity)-[:USES_DEPENDENCY]->(d:GraphEntity {id: 'Dependency:torch'}) RETURN m;
MATCH p=(f:GraphEntity {id: 'Finding:CVE-2026-0001'})-[*1..5]-(n:GraphEntity) RETURN p;
```

## Explicitly out of scope for this POC stage

This stage does not implement GraphRAG/LLM reasoning, multi-tenancy, production migrations, application/owner schema expansion, commercial/enterprise features, or any change to deterministic risk-scoring authority.

## Security and failure behavior

Graph content can reveal vulnerable packages, models, provenance gaps, and ownership. Do not log credentials or sensitive metadata. Use environment variables or secret managers for Memgraph credentials. Queries use parameterized property values and allowlisted relationship types. Graph failures should be treated as context-layer failures, not scanner failures, unless the operator explicitly makes graph population required. The default scanner remains offline-compatible and does not require Memgraph.

## Performance assumptions

The POC performs straightforward upserts and deduplicates nodes/relationships. It is suitable for technical validation and local development, not benchmark claims. Larger SBOMs may need batching, indexes on `GraphEntity.id`, query profiling, and lifecycle management for stale report snapshots.

## Maturity

- Production/current: manifest/model parsing, enrichment, deterministic scoring, policy evaluation, evidence outputs, and existing graph policy guardrails.
- Experimental graph: GraphStore, in-memory store, Memgraph adapter, report population, and graph queries.
- Out of scope now: GraphRAG/LLM reasoning and application/owner schema expansion.
- Roadmap: first-class application/owner schemas based on real report data, tested Memgraph integration in CI, graph indexes/migrations, tenant isolation, and richer impact paths.
