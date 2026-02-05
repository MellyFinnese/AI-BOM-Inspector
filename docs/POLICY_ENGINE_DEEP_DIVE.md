# Enterprise Policy Engine Deep Dive

Policies must be deterministic, explainable, and enforceable. This document captures the MVP evaluation model and the roadmap for enterprise-scale policy governance.

## Design principles

- Stateless evaluation
- Input-driven (AI-BOM + metadata)
- Human-readable definitions
- Machine-verifiable outcomes

## Policy structure (MVP)

```yaml
id: training-data-license-check
version: 1.0.0
severity: high
scope: model
conditions:
  all:
    - field: training_data.license
      operator: not_in
      values: ["Apache-2.0", "MIT"]
action: deny
```

## Supported operators (MVP)

- equals / not_equals
- in / not_in
- exists / not_exists
- matches (regex)

## Evaluation algorithm

1. Load active policy set.
2. Filter policies by scope.
3. Evaluate conditions.
4. Apply severity-based decisioning.
5. Emit structured explanation.

## Explainability output

Each decision emits:

- Policy ID
- Matched conditions
- Input values
- Final outcome

Example:

```json
{
  "policy_id": "training-data-license-check",
  "result": "fail",
  "reason": "training_data.license = Proprietary",
  "severity": "high"
}
```

## Performance targets

- In-memory policy compilation
- O(p × c) evaluation
- <50ms per asset target

## Roadmap

- Policy versioning + rollback
- Severity-based partial evaluation
- OPA/Rego compatibility layer
