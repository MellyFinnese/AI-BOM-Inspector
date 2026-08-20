# AI-BOM Inspector

![AI-BOM Inspector CI](https://img.shields.io/badge/AI--BOM%20Inspector-Scan%20your%20AI%20stack%20in%20CI-blue)

**Deterministic AI supply-chain risk and impact analysis.**

AI-BOM Inspector analyzes an AI project's dependencies, SBOMs, models, metadata, code, and artifacts, then turns the resulting evidence into a risk score, relationship context, behavioral drift signal, impact path, policy decision, and CI-friendly report.

The core design is **offline-first, deterministic, explainable, evidence-backed, and enforceable**.

## Project identity

This repository is the **canonical home for the AI-BOM Inspector implementation maintained by MellyFinnese**.

The project has evolved from AI supply-chain inventory and deterministic risk analysis into a broader impact-analysis workflow covering AI asset identity, provenance, JavaScript/TypeScript semantics, behavioral drift, attack-path reasoning, blast radius, and graph-backed investigation.

The repository itself is the source of truth for the architecture, implementation, benchmarks, security validation, and release history described here.

## The problem

Traditional SBOM tooling tells you what components exist.

AI systems need more context:

- What AI assets actually exist?
- What evidence indicates risk?
- How does a vulnerability or behavior change propagate through dependencies and models?
- Which applications, agents, deployments, and owners are affected?
- Did a code change create a newly reachable impact path?
- Should the change be allowed, warned on, or blocked?
- Can the decision be explained and reproduced?

AI-BOM Inspector is built around that decision loop.

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

### The important architectural boundary

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

The graph/context layer supplies identity, impact, traversal, behavioral change, and explanation. **The deterministic risk engine remains the scoring source of truth.** Graph databases such as Memgraph are optional rather than a requirement of the core engine.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the model and trust boundaries.

## AI impact analysis

The project now treats behavioral change as a graph problem rather than only a line-diff problem.

A semantic JavaScript/TypeScript scan can identify evidence-backed relationships such as:

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
         bound tool
              |
              v
       privileged operation
```

A behavioral diff can then answer:

> **Did this change create a new reachable impact path?**

The formal `AttackPath` model records:

- stable path identity
- source and target nodes
- ordered relationships
- severity
- supporting evidence

This makes the result reusable across CLI output, CI policy, graph export, AI-BOM context, and graph backends.

## One-command proof

The repository contains a reproducible vulnerable AI project:

```bash
PYTHONPATH=src bash demo/golden-vulnerable-ai/run_demo.sh
```

The repository also contains an end-to-end impact-analysis demo:

```text
examples/impact-demo/
   baseline/   -> expected safe behavior
   candidate/  -> newly introduced AI impact path
```

The impact demo exercises:

```text
source code
   -> semantic evidence
   -> graph relationships
   -> impact path
   -> behavioral drift
   -> CI decision
   -> graph investigation
```

The goal is **claim -> proof**, not just feature-list documentation.

## What the core engine covers

### AI supply-chain analysis

- Python, JavaScript/TypeScript, Go, and Java dependency manifests
- CycloneDX and SPDX SBOM ingestion
- AI model metadata and model-reference discovery
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
- integrity findings and audit evidence

### JavaScript / TypeScript analysis

- offline static AI-usage discovery
- provider and model-call detection
- Agent and tool relationship detection
- prompt and trust-boundary analysis
- HTTP, CLI, environment, and retrieval sources
- alias-aware provider and agent resolution
- explicit import/export relationship indexing
- bounded variable-level flow relationships
- cross-file relationship context
- behavioral drift between baseline and candidate scans

The JS/TS layer intentionally remains conservative. It does not claim complete JavaScript data-flow, framework semantics, or exploitability.

### Risk and governance

- deterministic risk scoring
- score explanations and risk breakdowns
- organizational context such as criticality and data sensitivity
- policy-as-code controls
- CI blocking / warning decisions
- diffing between scan results
- evidence packs and audit-oriented outputs

### Graph and impact reasoning

The internal graph/context model is designed for relationship questions rather than opaque scoring.

```text
vulnerability
   -> package
   -> AI framework
   -> model
   -> application
   -> owner
```

For code-level impact analysis, the graph can also represent:

```text
source
   -> prompt
   -> agent
   -> tool
   -> privileged operation
```

This supports:

- blast-radius analysis
- evidence traversal
- behavioral drift
- attack / impact paths
- relationship diffing
- graph export
- downstream investigation in optional graph backends

### Enterprise interoperability

- CycloneDX 1.7 output
- SPDX 3.0 output
- JSON / Markdown / HTML
- SARIF / GitHub-oriented CI outputs
- schema validation
- policy examples and governance mappings

## CLI impact-analysis commands

Run JavaScript/TypeScript analysis:

```bash
aibom js-scan path/to/project
```

Compare baseline and candidate behavior:

```bash
aibom behavior-diff baseline/ candidate/
```

Enumerate evidence-backed impact paths:

```bash
aibom attack-paths path/to/project
```

Export a backend-neutral graph payload:

```bash
aibom graph-export path/to/project --output graph.json
```

Use a CI-style gate when a new impact path is detected:

```bash
aibom behavior-diff baseline/ candidate/
```

A detected new impact path returns a non-zero exit status so the result can participate in CI policy enforcement.

## Memgraph and graph backends

Memgraph is an optional graph backend for investigation and relationship-heavy workloads. The core scanner does not require it.

The graph export format is backend-neutral so other graph systems can consume the same evidence relationships.

Example investigation query shape:

```cypher
MATCH p = (source)-[:EVIDENCE_PATH*1..8]->(sink)
WHERE source.kind = "input"
  AND sink.kind = "privileged-operation"
RETURN p;
```

The important architectural boundary is preserved: **graph traversal can explain impact, but it does not become the authoritative risk scorer.**

## AI-BOM context and provenance

The AI-BOM model treats AI assets as first-class objects, including models, model versions, datasets, training provenance, artifacts, runtimes, APIs, agents, prompts, tools, deployments, and evaluations.

The code-analysis graph is bridged into that model only where the evidence is AI-relevant. This keeps the strict core AI-BOM schema stable while allowing code-level findings to add context around agents, prompts, tools, models, APIs, and deployments.

That enables a longer reasoning chain such as:

```text
source code
   -> agent
   -> model
   -> model version
   -> artifact
   -> deployment
   -> application
```

## Benchmarking and validation

The project maintains a labeled JavaScript/TypeScript benchmark corpus with positive, clean-negative, and adversarial-negative cases.

The benchmark reports:

- overall precision / recall / F1
- per-detector metrics
- per-category metrics
- per-case false positives and false negatives
- regression coverage for corpus breadth

Benchmark categories include provider, agent, tool, MCP, taint, privileged operation, mixed behavior, clean negatives, and adversarial lookalikes.

The purpose is to measure detector quality rather than reward a small set of happy-path fixtures.

## Security is part of the product

AI-BOM Inspector does not treat passing functional tests as enough for a security tool.

The project uses an adversarial loop:

```text
Build
  -> attack assumptions
  -> reproduce failures safely
  -> add regression tests
  -> fix confirmed issues
  -> rerun the suite
  -> repeat
```

Recent adversarial hardening has targeted:

- policy bypasses
- resource-exhaustion paths
- malformed policy input
- dangerous pickle references
- dynamic-analysis severity inflation
- graph identity confusion
- trust-root replacement
- attestation/signature ambiguity
- JavaScript/TypeScript analyzer false positives
- impact-path regression

See [docs/SECURITY_VALIDATION.md](docs/SECURITY_VALIDATION.md).

## Security invariants

The project explicitly distinguishes:

- **integrity digest** from **cryptographic signature**
- **self-consistent trust root** from **externally trusted root**
- **missing evidence** from **positive evidence**
- **canonical component identity** from **name-only matching**
- **controlled policy failure** from **silent exceptions**
- **changed code relationships** from **newly reachable impact paths**

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
| Golden vulnerable-AI demo | **Core proof path** |
| Impact-analysis demo | **Core proof path** |
| Adversarial regression coverage | **Core security practice** |
| CycloneDX / SPDX reporting | **Core** |
| GitHub / CI integration | **Core integration** |
| Backend-neutral graph export | **Core integration** |
| Memgraph adapter | **Optional / experimental** |
| Sigstore signing | **Requires signing/provisioning; unsigned state is explicit when unavailable** |
| Enterprise control plane | **Roadmap / deployment architecture** |

## Security posture

The default posture is offline:

```bash
aibom scan --format json
```

Use `--online` only when a specific enrichment source is needed. Use `--local-only` / safe mode when an environment must not perform outbound requests.

The README intentionally does not describe a SHA-256 digest as a signature. Where real Sigstore signing is unavailable, attestations make the unsigned state explicit.

## Quick start

Install for development:

```bash
pip install -e '.[dev]'
```

Run a scan:

```bash
aibom scan --models-file models.json --format html --output report.html
```

Import an SBOM:

```bash
aibom scan --sbom-file path/to/cyclonedx.json --format html --output report.html
```

Fail CI below a health threshold:

```bash
aibom scan --fail-on-score 70 --format json
```

Compare reports:

```bash
aibom diff aibom-report-old.json aibom-report-new.json
```

Run JavaScript/TypeScript analysis:

```bash
aibom js-scan path/to/project
```

Run the benchmark corpus:

```bash
aibom benchmark benchmarks/javascript/manifest.json
```

Run tests:

```bash
pytest
```

Run the focused adversarial suite:

```bash
pytest tests/test_adversarial_hardening.py -v
```

## Repository map

```text
src/aibom_inspector/
  parsers.py              # typed input validation + safe input limits
  dependency_scanner.py   # dependency discovery and analysis
  model_inspector.py      # model metadata / artifact analysis
  pickle_inspector.py     # static pickle inspection
  dynamic_analysis.py     # guarded dynamic findings
  graph.py                # relationship / blast-radius context
  ai_assets.py            # AI-BOM schema and relationship index
  ai_bom_reasoning.py     # identity, lineage, blast radius, attack paths
  js_analysis.py          # JavaScript/TypeScript evidence analysis
  js_semantics.py         # aliases, imports/exports, variable flow
  behavioral_drift.py     # evidence-graph change and impact-path diffing
  benchmarking.py         # reproducible detector benchmarks
  risk_engine.py          # deterministic scoring
  policy.py               # policy decisions and enforcement
  reporting.py            # report generation
  attestation.py          # provenance / evidence artifacts
  trust_root.py           # trust-root and verification primitives

crates/
  core/                   # Rust core
  licenses/               # license rules
  advisories/             # advisory ingestion adapters
  report/                 # reporting and diff support

demo/golden-vulnerable-ai/
  # reproducible vulnerable AI project used as the proof path

examples/impact-demo/
  # baseline/candidate impact-analysis proof path

benchmarks/javascript/
  # labeled JS/TS benchmark corpus, including adversarial negatives

tests/
  # functional, golden-demo, policy, parser, security, semantic, drift, and regression tests

docs/
  ARCHITECTURE.md
  SECURITY_VALIDATION.md
  POLICY.md
  SCORING.md
  ENTERPRISE_TRUST_BASELINE.md
  POLICY_COOKBOOK.md
  AI_SUPPLY_CHAIN_THREAT_MODEL.md
```

## What makes the project different

**AI assets are first-class.** Models, datasets, deployments, agents, prompts, tools, and artifacts can be represented as explicit supply-chain objects instead of opaque files.

**The decision is deterministic.** The core security result does not depend on hosted LLM inference.

**Relationships matter.** The graph/context layer explains impact, lineage, blast radius, and behavioral change across dependencies, code, models, applications, and owners.

**Impact paths are explicit.** A newly reachable input-to-side-effect path is represented as a first-class, evidence-backed object rather than an unexplained alert.

**Evidence matters.** Findings and relationships are intended to remain traceable to the observations that produced them.

**The scanner is attacked too.** Security failures and analyzer weaknesses are turned into regression tests and hardened rather than simply documented.

## Technical conversation: the graph problem

A useful graph question is not simply "can this data live in a graph database?"

It is:

> **Where does a graph materially improve AI supply-chain reasoning over a local representation?**

For example:

```text
CVE
  -> package
  -> framework
  -> model
  -> application
  -> owner
```

And for AI application behavior:

```text
HTTP input
  -> prompt
  -> agent
  -> tool
  -> privileged operation
```

The second graph is especially useful when comparing versions:

```text
baseline:   input -> prompt -> model
candidate:  input -> prompt -> agent -> tool -> privileged operation
```

The architecture can then report the **newly reachable path** rather than merely reporting that a file changed.

The architecture is intentionally backend-neutral so a graph database can be introduced where it provides measurable value without making the deterministic core dependent on it.

## Development milestones

The project's architecture has progressed through focused, reviewable milestones:

- **AI-BOM identity, lineage, and blast-radius foundations**
- **JavaScript/TypeScript analysis and behavioral drift**
- **Benchmark v2 with per-detector and per-category metrics**
- **Adversarial benchmark corpus and negative-case coverage**
- **Semantic JS/TS aliases and cross-file relationships**
- **Graph-aware behavioral drift and impact-path reasoning**
- **End-to-end AI impact-path analysis and graph export**

The implementation is deliberately evolving through evidence-backed milestones rather than a single monolithic scanner release.

## Further reading

- [Architecture](docs/ARCHITECTURE.md)
- [Security validation](docs/SECURITY_VALIDATION.md)
- [Policy](docs/POLICY.md)
- [Scoring](docs/SCORING.md)
- [Enterprise Trust Baseline](docs/ENTERPRISE_TRUST_BASELINE.md)
- [AI supply-chain threat model](docs/AI_SUPPLY_CHAIN_THREAT_MODEL.md)
- [Policy cookbook](docs/POLICY_COOKBOOK.md)
- [Quickstart](docs/QUICKSTART.md)
- [Security reporting](SECURITY.md)

## Project status

AI-BOM Inspector is an actively evolving security-engineering project. The repository contains working core capabilities, conservative analysis components, experimental integrations, and roadmap material; the status table above is the authoritative distinction.

The project is intended to make AI supply-chain decisions **traceable, reproducible, testable, explainable, and enforceable**.
