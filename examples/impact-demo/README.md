# End-to-end impact demo

This demo shows the intended security workflow: a harmless AI application is changed so an untrusted request can reach a privileged process operation.

## Scan the candidate

```bash
aibom js-scan examples/impact-demo/candidate
aibom attack-paths examples/impact-demo/candidate
```

`attack-paths` is intentionally a CI-style command: it exits non-zero when an input-to-side-effect path is discovered.

## Compare baseline and candidate

```bash
aibom behavior-diff examples/impact-demo/baseline examples/impact-demo/candidate
```

The expected result includes `impact_path_added: true` and an evidence-backed path resembling:

```text
HTTP input -> prompt -> privileged operation
```

The exact node identifiers are deterministic scan artifacts and may include file/line information.

## Export for graph analysis

```bash
aibom graph-export examples/impact-demo/candidate /tmp/impact-graph.json
```

The payload follows `aibom-js-graph.v1` and is backend-neutral.
