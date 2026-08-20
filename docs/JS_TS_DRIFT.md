# JavaScript / TypeScript analysis and behavioral drift

AI-BOM Inspector now analyzes JavaScript and TypeScript without executing the target project or installing its npm dependencies.

## CLI

```bash
aibom js-scan ./app --output js-analysis.json
```

The output is deterministic JSON containing detector IDs, file/line evidence, confidence, nodes, and relationships.

## Behavioral drift

```bash
aibom behavior-diff baseline.json candidate.json
```

or compare two directories directly:

```bash
aibom behavior-diff ./baseline ./candidate
```

The drift engine looks for changes in evidence-backed relationships, not just text changes. A new input → prompt → privileged-operation path is surfaced as `impact_path_added` and causes a non-zero CLI exit so it can gate CI.

The initial implementation is deliberately conservative: it uses tolerant lexical patterns and same-file relationship construction rather than claiming whole-program data-flow precision. Detector IDs and evidence are stable enough for regression testing and benchmark tracking.

## Benchmarking

The labeled corpus lives under `benchmarks/javascript/`.

```bash
aibom benchmark benchmarks/javascript/manifest.json --fail-below-f1 0.90
```

The benchmark reports precision, recall, F1, and per-case false positives/negatives. New detectors should add fixtures and labels before being promoted to a default gate.

## Product surface

The CLI exposes four user-facing entry points:

- `aibom js-scan` — inspect JS/TS AI usage.
- `aibom behavior-diff` — detect newly reachable AI/security behavior.
- `aibom benchmark` — measure detector quality reproducibly.
- `aibom serve` — serve reports and demo artifacts locally with Python's standard library.

The existing HTML renderer and golden vulnerable-AI demo remain the primary proof surfaces; these commands make them easier to discover and reuse.
