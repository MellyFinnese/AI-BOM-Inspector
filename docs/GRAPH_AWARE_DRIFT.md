# Graph-aware behavioral drift

AI-BOM Inspector compares semantic JS/TS evidence graphs rather than treating every source change as equally important.

## What it detects

The drift engine builds bounded evidence paths from untrusted input nodes to side-effect nodes such as tool bindings and privileged operations. It compares the baseline and candidate path sets and reports paths that are newly reachable.

A newly introduced path is emitted as `impact_path_added` with:

- the exact node sequence
- relationship sequence
- path length
- severity (`medium`, `high`, or `critical`)
- aggregate counts of added/removed impact paths

The CLI continues to return exit code `2` when at least one new impact path is present, making the result usable as a CI deployment gate.

## Example

Conceptually, a safe baseline may contain:

```text
HTTP input -> prompt
```

while a candidate introduces:

```text
HTTP input -> prompt -> privileged operation
```

The candidate is reported as a newly reachable impact path rather than merely a changed line.

## Scope and guarantees

The implementation is deliberately bounded and deterministic. It traverses the evidence graph to a small maximum depth, avoids cycles, and limits the number of paths returned. It does **not** claim complete JavaScript data-flow, framework semantics, or exploitability.

The intended guarantee is narrower and auditable:

> A path is reported when the analyzer has evidence-backed graph relationships connecting a discovered input boundary to a discovered side-effect node, and that path was absent from the baseline graph.
