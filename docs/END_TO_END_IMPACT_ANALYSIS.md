# End-to-end AI impact analysis

AI-BOM Inspector now has a complete evidence path from JS/TS behavior to AI-BOM context and graph backends:

```text
JS/TS source
  -> semantic evidence graph
  -> formal impact paths
  -> behavioral drift
  -> AI-relevant AIBOM context
  -> backend-neutral graph payload
  -> Memgraph exploration
```

## Formal attack paths

`attack_paths.py` models an impact path as:

- stable path identity
- source node
- target node
- ordered node sequence
- ordered relationship sequence
- severity
- evidence file references

Traversal is bounded and cycle-safe. It is evidence discovery, not exploitability proof.

## Behavioral drift

`behavioral_drift.py` compares baseline and candidate impact-path sets. A path that exists only in the candidate is emitted as `impact_path_added` and causes the existing CLI to exit non-zero.

## AI-BOM bridge

`js_ai_bom_bridge.py` converts AI-relevant code nodes into the existing strict AI-BOM asset vocabulary (`api`, `model`, `agent`, `prompt`, `tool`) and stores code graph/path provenance under document metadata. The core AI-BOM schema is not widened with code-only node types.

## Graph backends

`graph_payload.py` emits `aibom-js-graph.v1`, a backend-neutral node/edge representation. The Memgraph example projects this into `AIJS` nodes and `EVIDENCE` relationships while preserving the original analyzer relationship in a relationship property.

## Demo

See `examples/impact-demo/README.md` and `examples/memgraph/README.md` for the full workflow.
