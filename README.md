# AI-BOM Inspector

![AI-BOM Inspector CI](https://img.shields.io/badge/AI--BOM%20Inspector-Scan%20your%20AI%20stack%20in%20CI-blue)

**Deterministic AI supply-chain risk and impact analysis.**

AI-BOM Inspector analyzes dependencies, SBOMs, AI models, metadata, artifacts, and source code, then turns the resulting evidence into deterministic risk, relationship context, behavioral drift, impact paths, policy decisions, and CI-friendly reports.

The core design is **offline-first, deterministic, explainable, evidence-backed, and enforceable**.

## Validation snapshot

The current regression suite passes:

```text
152 tests passed
1 skipped
0 failed
```

The labeled JavaScript/TypeScript benchmark currently reports:

```text
30 benchmark cases
Precision: 93.94%
Recall:    95.38%
F1:        94.66%
```

The benchmark contains positive, clean-negative, and adversarial-negative cases. The quality gate remains **precision, recall, and F1 >= 0.90**.

## Project identity

This repository is the **canonical home for the AI-BOM Inspector implementation maintained by MellyFinnese**.

The project has evolved from AI supply-chain inventory and deterministic risk analysis into a broader impact-analysis workflow covering AI asset identity, provenance, JavaScript/TypeScript semantics, behavioral drift, attack-path reasoning, blast radius, and graph-backed investigation.

The repository is the source of truth for the architecture, implementation, benchmarks, security validation, and release history described here.

## The core flow

```text
AI project
   |
   +--> SBOM / manifests / model metadata / artifacts / source code
   |
   v
Discovery + parsing
   |
   v
Normalization + identity
   |
   v
Evidence + relationship context
   |
   +--> JS/TS semantic analysis
   |        |
   |        v
   |    Behavioral drift
   |        |
   |        v
   |    Impact / attack paths
   |
   v
Deterministic risk engine
   |
   v
Policy engine
   |
   v
Report / CI decision / evidence pack / graph export
```

### Architectural boundary

```text
                    Relationship + impact context
                                 |
SBOM / Models / Code -> Evidence Graph -> Impact Paths
                         |              |
                         v              v
                  Deterministic Risk -> Policy -> Enforcement
                         ^
                         |
                  scoring source of truth
```

The graph/context layer provides identity, traversal, impact, behavioral change, and explanation. **The deterministic risk engine remains the scoring source of truth.** Memgraph and other graph databases are optional backends rather than requirements of the core engine.

## Impact analysis

The project treats behavioral change as a graph problem rather than only a line-diff problem.

A semantic JavaScript/TypeScript scan can represent relationships such as:

```text
HTTP / CLI / env / retrieval input
              |
              v
           prompt
              |
              v
            agent
              |
              v
             tool
              |
              v
       privileged operation
```

The formal `AttackPath` model records stable path identity, source and target nodes, ordered relationships, severity, and supporting evidence.

A behavioral diff can therefore answer:

> **Did this change create a new reachable impact path?**

That result can feed CLI output, CI policy, graph export, AI-BOM context, and graph backends.

## AI-BOM identity and provenance

AI assets are first-class objects, including:

```text
Dataset
  ↓
Training Run
  ↓
Fine-Tuned Model
  ↓
Model Version
  ↓
Artifact
  ↓
Deployment
  ↓
API
  ↓
Agent
  ↓
Prompt
  ↓
Tool
```

The AI-BOM layer carries identity, provenance, lineage, evidence, deployment context, and evaluations. Code-analysis evidence is bridged into the AI-BOM only where it is AI-relevant, keeping the core schema strict.

## What the core engine covers

### AI supply-chain analysis

- Python, JavaScript/TypeScript, Go, and Java manifests
- CycloneDX and SPDX SBOM ingestion
- AI model metadata and reference discovery
- dependency pinning and version posture
- model freshness and provenance signals
- license and governance analysis
- local and optional remote advisory enrichment

### Model and artifact security

- model artifact hashing
- Safetensors inspection
- pickle/global analysis
- guarded dynamic inspection groundwork
- legacy pickle policy enforcement
- integrity findings and evidence output

### JavaScript / TypeScript analysis

- offline static AI-usage discovery
- provider and model-call detection
- Agent and tool relationships
- prompt and trust-boundary analysis
- HTTP, CLI, environment, and retrieval sources
- alias-aware provider and agent resolution
- import/export relationship indexing
- bounded variable-level flow relationships
- cross-file relationship context
- behavioral drift between baseline and candidate scans

The JS/TS layer is intentionally conservative. It does not claim complete JavaScript data-flow, framework semantics, or exploitability.

### Risk and governance

- deterministic risk scoring
- score explanations and risk breakdowns
- organizational context such as criticality and data sensitivity
- policy-as-code controls
- CI blocking / warning decisions
- report diffing
- evidence packs and audit-oriented outputs

### Graph and impact reasoning

The graph/context model supports:

- blast-radius analysis
- evidence traversal
- behavioral drift
- attack / impact paths
- relationship diffing
- backend-neutral graph export
- downstream investigation in optional graph backends

For code-level reasoning:

```text
source -> prompt -> agent -> tool -> privileged operation
```

## CLI

Run JavaScript/TypeScript analysis:

```bash
aibom js-scan path/to/project
```

Compare baseline and candidate behavior:

```bash
aibom behavior-diff baseline/ candidate/
```

Enumerate impact paths:

```bash
aibom attack-paths path/to/project
```

Export graph context:

```bash
aibom graph-export path/to/project --output graph.json
```

Run the benchmark:

```bash
aibom benchmark benchmarks/javascript/manifest.json
```

Run the full test suite:

```bash
pytest
```

## Memgraph

Memgraph is an optional investigation backend. The exported graph is backend-neutral.

Example query shape:

```cypher
MATCH p = (source)-[:EVIDENCE_PATH*1..8]->(sink)
WHERE source.kind = "input"
  AND sink.kind = "privileged-operation"
RETURN p;
```

The architecture deliberately keeps graph traversal separate from authoritative risk scoring.

## Benchmarking and security validation

The benchmark reports:

- overall precision / recall / F1
- per-detector metrics
- per-category metrics
- per-case false positives and false negatives
- regression coverage for corpus breadth

Current result:

```text
Cases:     30
Precision: 93.94%
Recall:    95.38%
F1:        94.66%
```

The adversarial regression loop is:

```text
Build
  -> attack assumptions
  -> reproduce failures safely
  -> add regression coverage
  -> fix the underlying issue
  -> rerun the suite
```

The benchmark specifically includes clean negatives and adversarial lookalikes so detector improvements are measured against false positives as well as missed findings.

## Proof paths

Reproducible vulnerable-AI demo:

```bash
PYTHONPATH=src bash demo/golden-vulnerable-ai/run_demo.sh
```

End-to-end impact-analysis demo:

```text
examples/impact-demo/
  baseline/
  candidate/
```

The goal is **claim -> proof**, not a feature list.

## Security invariants

The project explicitly distinguishes:

- **integrity digest** from **cryptographic signature**
- **self-consistent trust root** from **externally trusted root**
- **missing evidence** from **positive evidence**
- **canonical identity** from **name-only matching**
- **controlled policy failure** from **silent exceptions**
- **changed relationships** from **newly reachable impact paths**

These distinctions matter because the scanner itself is a security boundary.

## Core vs experimental

| Capability | Status |
| --- | --- |
| Deterministic risk engine | **Core** |
| Policy enforcement | **Core** |
| SBOM / manifest parsing | **Core** |
| Model and artifact analysis | **Core** |
| AI asset identity / lineage | **Core** |
| Graph-based impact context | **Core** |
| JavaScript/TypeScript semantic analysis | **Core capability; conservative semantics** |
| Behavioral drift | **Core capability** |
| Formal impact / attack paths | **Core capability** |
| Adversarial regression coverage | **Core security practice** |
| CycloneDX / SPDX reporting | **Core** |
| GitHub / CI integration | **Core integration** |
| Backend-neutral graph export | **Core integration** |
| Memgraph adapter | **Optional / experimental** |
| Enterprise control plane | **Roadmap / deployment architecture** |

## Repository map

```text
src/aibom_inspector/
  ai_assets.py            # AI-BOM schema and relationship index
  ai_bom_reasoning.py     # identity, lineage, blast radius, attack paths
  js_analysis.py          # JS/TS evidence analysis
  js_semantics.py         # aliases, imports/exports, variable flow
  behavioral_drift.py     # evidence-graph change and impact-path diffing
  benchmarking.py         # reproducible detector benchmarks
  graph.py                # relationship / blast-radius context
  risk_engine.py          # deterministic scoring
  policy.py               # policy decisions and enforcement
  reporting.py            # report generation
  attestation.py          # evidence artifacts
  trust_root.py           # trust primitives

crates/
  core/                   # Rust core
  licenses/               # license rules
  advisories/             # advisory adapters
  report/                 # reporting and diff support

demo/golden-vulnerable-ai/
examples/impact-demo/
benchmarks/javascript/
tests/
docs/
```

## What makes it different

**AI assets are first-class.** Models, datasets, deployments, agents, prompts, tools, and artifacts can be represented explicitly.

**The decision is deterministic.** The core security result does not require hosted LLM inference.

**Relationships matter.** The graph/context layer explains lineage, blast radius, and behavioral change.

**Impact paths are explicit.** A newly reachable input-to-side-effect path becomes a first-class, evidence-backed object.

**Evidence matters.** Findings and relationships remain traceable to the observations that produced them.

**The scanner is attacked too.** Analyzer weaknesses become regression tests and hardened behavior.

## Development milestones

- **AI-BOM identity, lineage, and blast-radius foundations**
- **JavaScript/TypeScript analysis and behavioral drift**
- **Benchmark v2 with per-detector and per-category metrics**
- **Adversarial benchmark corpus and negative-case coverage**
- **Semantic JS/TS aliases and cross-file relationships**
- **Graph-aware behavioral drift and impact-path reasoning**
- **End-to-end AI impact-path analysis and graph export**
- **Benchmark hardening to >0.90 precision/recall/F1**

The implementation is deliberately evolving through evidence-backed milestones rather than a single monolithic scanner release.

## Further reading

- [Architecture](docs/ARCHITECTURE.md)
- [Security validation](docs/SECURITY_VALIDATION.md)
- [Policy](docs/POLICY.md)
- [Scoring](docs/SCORING.md)
- [Enterprise Trust Baseline](docs/ENTERPRISE_TRUST_BASELINE.md)
- [Policy Cookbook](docs/POLICY_COOKBOOK.md)
- [AI Supply Chain Threat Model](docs/AI_SUPPLY_CHAIN_THREAT_MODEL.md)
