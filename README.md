# AI-BOM Inspector

![AI-BOM Inspector CI](https://img.shields.io/badge/AI--BOM%20Inspector-Scan%20your%20AI%20stack%20in%20CI-blue)

**Deterministic AI supply-chain risk analysis.**

AI-BOM Inspector analyzes an AI project's dependencies, SBOMs, models, metadata, and artifacts, then turns the resulting evidence into a risk score, impact context, policy decision, and CI-friendly report.

The core design is **offline-first, deterministic, explainable, and enforceable**.

## The problem

Traditional SBOM tooling tells you what components exist.

AI systems need more context:

- What AI assets actually exist?
- What evidence indicates risk?
- How does a vulnerability propagate through dependencies and models?
- Which applications and owners are affected?
- Should the change be allowed, warned on, or blocked?
- Can the decision be explained and reproduced?

AI-BOM Inspector is built around that decision loop.

## The core flow

```text
AI project
   |
   +--> SBOM / manifests / model metadata / artifacts
   |
   v
Discovery + parsing
   |
   v
Normalization
   |
   v
Evidence + relationship context
   |
   v
Deterministic risk engine
   |
   v
Policy engine
   |
   v
Report / CI decision / evidence pack
```

### The important architectural boundary

```text
                    Relationship context
                           |
SBOM / Models -> Evidence + Graph -> Risk -> Policy -> Enforcement
                                      ^
                                      |
                         deterministic source of truth
```

The graph/context layer supplies impact, traversal, and explanation. **The deterministic risk engine remains the scoring source of truth.** A graph database such as Memgraph is optional rather than a requirement of the core engine.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the complete model and trust boundaries.

## One-command proof

The repository contains a reproducible vulnerable AI project:

```bash
PYTHONPATH=src bash demo/golden-vulnerable-ai/run_demo.sh
```

The demo exercises the end-to-end path:

```text
vulnerable AI project
      -> scan
      -> findings
      -> risk decision
      -> policy evaluation
      -> evidence/report
      -> CI-style enforcement
```

The demo also includes application-to-owner context so graph impact can answer questions such as:

```text
CVE
 -> package
 -> model
 -> application
 -> owner
```

The goal is **claim -> proof**, not just feature-list documentation.

## What the core engine covers

### AI supply-chain analysis

- Python, JavaScript, Go, and Java dependency manifests
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

### Risk and governance

- deterministic risk scoring
- score explanations and risk breakdowns
- organizational context such as criticality and data sensitivity
- policy-as-code controls
- CI blocking / warning decisions
- diffing between scan results
- evidence packs and audit-oriented outputs

### Graph and impact reasoning

The internal graph/context model is designed for relationship questions rather than opaque scoring:

```text
vulnerability
   -> package
   -> AI framework
   -> model
   -> application
   -> owner
```

This supports blast-radius analysis, evidence traversal, and attack-path reasoning.

### Enterprise interoperability

- CycloneDX 1.7 output
- SPDX 3.0 output
- JSON / Markdown / HTML
- SARIF / GitHub-oriented CI outputs
- schema validation
- policy examples and governance mappings

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

See [docs/SECURITY_VALIDATION.md](docs/SECURITY_VALIDATION.md).

## Security invariants

The project explicitly distinguishes:

- **integrity digest** from **cryptographic signature**
- **self-consistent trust root** from **externally trusted root**
- **missing evidence** from **positive evidence**
- **canonical component identity** from **name-only matching**
- **controlled policy failure** from **silent exceptions**

These distinctions matter because the scanner itself is a security boundary.

## Core vs experimental

| Capability | Status |
| --- | --- |
| Deterministic risk engine | **Core** |
| Policy enforcement | **Core** |
| SBOM / manifest parsing | **Core** |
| Model and artifact analysis | **Core** |
| Graph-based impact context | **Core** |
| Golden vulnerable-AI demo | **Core proof path** |
| Adversarial regression coverage | **Core security practice** |
| CycloneDX / SPDX reporting | **Core** |
| GitHub / CI integration | **Core integration** |
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

tests/
  # functional, golden-demo, policy, parser, security, and regression tests

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

**AI assets are first-class.** Models and artifacts are analyzed alongside ordinary dependencies instead of being treated as opaque files.

**The decision is deterministic.** The core security result does not depend on hosted LLM inference.

**Relationships matter.** The graph/context layer can explain impact and blast radius across dependencies, models, applications, and owners.

**Evidence matters.** Findings are intended to remain traceable to the observations and relationships that produced them.

**The scanner is attacked too.** Security failures are turned into regression tests and hardened rather than simply documented.

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

That relationship chain turns an isolated vulnerability into an explainable blast-radius problem.

The architecture is intentionally backend-neutral so a graph database can be introduced where it provides measurable value without making the deterministic core dependent on it.

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

AI-BOM Inspector is an actively evolving security-engineering project. The repository contains working core capabilities, experimental components, and roadmap material; the status table above is the authoritative distinction.

The project is intended to make AI supply-chain decisions **traceable, reproducible, testable, and enforceable**.
