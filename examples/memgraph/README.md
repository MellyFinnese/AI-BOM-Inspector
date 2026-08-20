# Memgraph impact-path workflow

This example keeps the JS/TS evidence graph backend-neutral in the core project and provides a thin Memgraph projection for graph exploration.

## Export

```bash
aibom graph-export examples/impact-demo/candidate /tmp/impact-graph.json
```

## Load

Use the JSON payload as `$nodes` and `$edges` with `impact-paths.cypher`. The ingestion creates `AIJS` nodes and generic `EVIDENCE` relationships while preserving the analyzer's original relationship type in `r.relationship`.

## Query

The included Cypher finds input-to-privileged-operation paths and supports bounded downstream traversal from a selected node.

This is intentionally separate from the risk engine: graph traversal is context and impact evidence, not the deterministic risk score.
