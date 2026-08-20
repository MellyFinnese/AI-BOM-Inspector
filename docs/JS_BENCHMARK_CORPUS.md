# JavaScript / TypeScript benchmark corpus

The JS/TS benchmark is a labeled regression corpus for the static analyzer. It measures detector behavior rather than code volume.

## Coverage

The corpus intentionally includes both positive and negative examples across:

- AI providers and model-call variants
- agents and bound tools
- MCP clients and servers
- HTTP, CLI, environment, and retrieval trust boundaries
- privileged filesystem and network operations
- mixed AI applications
- CommonJS as well as TypeScript/ES module syntax
- ordinary business code
- comments and strings containing AI-looking text
- dead code and adversarial lookalikes

The current target is at least 20 labeled cases, with explicit `clean-negative` and `adversarial-negative` categories.

## Why negatives matter

A static security analyzer is not useful if it turns documentation, strings, dead code, or ordinary application code into findings. Negative fixtures therefore count toward false-positive measurement and remain part of the regression suite.

## Metrics

`aibom-benchmark.v2` reports:

- overall precision, recall, and F1
- per-detector precision, recall, and F1
- per-category precision, recall, and F1
- per-case true positives, false positives, and false negatives

A strong aggregate score should never be treated as proof that every detector is strong. Review the per-detector results before promoting a detector into a CI quality gate.

## Running it

```bash
PYTHONPATH=src python -m aibom_inspector benchmark benchmarks/javascript/manifest.json
```

For CI, use the existing F1 threshold option:

```bash
PYTHONPATH=src python -m aibom_inspector benchmark \
  benchmarks/javascript/manifest.json \
  --fail-below-f1 0.90
```

The corpus is deliberately dependency-free and does not install or execute the target JavaScript/TypeScript applications.
