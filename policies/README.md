# Policies

Policy files keep build-time guardrails versioned with the codebase. The schema is defined in `schemas/policy.schema.json` and reference examples live in `policies/examples/`.

Use `aibom_inspector.policy.load_policy` to parse a YAML policy and `evaluate_policy` to apply it to a generated report. The helper will apply exceptions, check trust scores, and emit structured failures that CI can surface.
