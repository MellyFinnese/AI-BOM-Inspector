# Optional Graph Architecture and Memgraph POC

## Repository audit summary

AI-BOM Inspector currently scans project manifests and model metadata, enriches dependencies/models with local or optional network intelligence, scores risk deterministically, evaluates policy, and renders reports/CI artifacts. The implemented flow is:

```text
Input / Parsers
  -> Normalization into DependencyInfo and ModelInfo
  -> Enrichment (OSV, model advisories, licenses, trust signals, stack discovery)
  -> Default scoring model in the risk engine
  -> Policy engine and graph-policy guardrails
  -> Reports, attestations, evidence packs, SARIF/SBOM outputs
```

Implemented entities verified in source and tests include dependencies, dependency issues, models, model issues, licenses/license categories, model lineage fields, training source fields, stack-discovery graph nodes/edges, runtime traces, policies, policy violations, integrity findings, reports, evidence/export artifacts, audit logs, and deterministic score explanations.

Partially implemented or context-dependent entities include applications, owners, and production assets: organizational context exists for scoring, and stack discovery can find tools/providers/models/env vars, but the current report model does not contain a first-class application/owner schema. Those relationships are supported by the GraphStore when supplied by future/imported data, but the report ingester does not fabricate them.

Documented/planned concepts include enterprise control-plane ingestion, richer policy workflows, and roadmap items in the docs. They should not be represented as fully implemented unless backed by the source paths that implement them.

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

The report ingester creates only relationships supported by current data:

- `Report -[:CONTAINS]-> Dependency`
- `Report -[:CONTAINS]-> Model`
- `Dependency -[:DECLARED_LICENSE]-> License`
- `Model -[:DECLARED_LICENSE]-> License`
- `Dependency -[:AFFECTED_BY]-> Vulnerability` when an issue contains a CVE/advisory identifier
- `Model -[:AFFECTED_BY]-> Vulnerability` when a model issue contains a CVE/advisory identifier
- `Model -[:DERIVED_FROM]-> Model` from `base_models` and `fine_tuned_from`
- `Model -[:TRAINED_ON]-> TrainingSource`
- `Finding -[:EVIDENCED_BY]-> Dependency|Model`

The abstraction also supports future/imported relationships that the current report schema does not always provide:

- `Model -[:USES_DEPENDENCY]-> Dependency`
- `Application -[:USES_MODEL]-> Model`
- `Application -[:USES_DEPENDENCY]-> Dependency`
- `Application -[:OWNED_BY]-> Owner`
- `Application -[:GOVERNED_BY]-> Policy`

When current scan data lacks a direct model-to-dependency or application-owner relationship, queries return empty evidence rather than inventing links.

## Memgraph integration

`GraphStore` is a small protocol with an in-memory implementation and a Memgraph adapter. The Memgraph adapter uses the optional `neo4j` Python driver over Bolt and writes Cypher with parameterized values. Relationship types are allowlisted because Cypher cannot parameterize labels/types.

Environment variables:

- `AIBOM_MEMGRAPH_URI` defaults to `bolt://localhost:7687`
- `AIBOM_MEMGRAPH_USER` defaults to empty
- `AIBOM_MEMGRAPH_PASSWORD` defaults to empty

Local development:

```bash
docker compose -f examples/memgraph/docker-compose.yml up -d
pip install '.[memgraph]'
aibom graph populate --report examples/demo/aibom-report.json --backend memgraph
```

Example Cypher queries:

```cypher
MATCH (m:GraphEntity {label: 'Model'})-[:AFFECTED_BY]->(v:GraphEntity {id: 'Vulnerability:CVE-2026-0001'}) RETURN m;
MATCH (m:GraphEntity)-[:USES_DEPENDENCY]->(d:GraphEntity {id: 'Dependency:torch'}) RETURN m;
MATCH (a:GraphEntity)-[:USES_MODEL]->(m:GraphEntity)-[:USES_DEPENDENCY]->(d:GraphEntity {id: 'Dependency:torch'}) RETURN a, m, d;
MATCH (a:GraphEntity)-[:OWNED_BY]->(o:GraphEntity) RETURN a, o;
MATCH p=(f:GraphEntity {id: 'Finding:CVE-2026-0001'})-[*1..5]-(n:GraphEntity) RETURN p;
```

## GraphRAG status

`aibom graph ask` is an experimental evidence-retrieval POC. It retrieves structured graph evidence from an in-memory graph built from an existing report. It does not call an LLM and does not determine or override risk scores. A future LLM layer may summarize returned evidence, but deterministic scoring remains authoritative.

## Security and failure behavior

Graph content can reveal vulnerable packages, models, provenance gaps, and ownership. Do not log credentials or sensitive metadata. Use environment variables or secret managers for Memgraph credentials. Queries use parameterized property values and allowlisted relationship types. Graph failures should be treated as context-layer failures, not scanner failures, unless the operator explicitly makes graph population required. The default scanner remains offline-compatible and does not require Memgraph.

## Performance assumptions

The POC performs straightforward upserts and deduplicates nodes/relationships. It is suitable for technical validation and local development, not benchmark claims. Larger SBOMs may need batching, indexes on `GraphEntity.id`, query profiling, and lifecycle management for stale report snapshots.

## Maturity

- Production/current: manifest/model parsing, enrichment, deterministic scoring, policy evaluation, evidence outputs, and existing graph policy guardrails.
- Experimental graph: GraphStore, in-memory store, Memgraph adapter, report population, and graph queries.
- Experimental GraphRAG: structured graph evidence retrieval only; no production LLM answer generation.
- Roadmap: first-class application/owner schemas, tested Memgraph integration in CI, graph indexes/migrations, multi-tenant isolation, and richer impact paths.
