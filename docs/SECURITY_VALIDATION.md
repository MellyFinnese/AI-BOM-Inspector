# Security Validation

AI-BOM Inspector is security tooling, so the project evaluates itself adversarially rather than treating passing functional tests as sufficient.

## Validation loop

```text
Build
  -> attack the assumptions
  -> reproduce failures safely
  -> add regression tests
  -> fix confirmed issues
  -> re-run the suite
  -> repeat
```

## Current adversarial coverage

The security regression suite targets failure classes including:

- policy enforcement bypasses
- oversized untrusted inputs
- malformed policy data
- dangerous model-artifact references
- dynamic-analysis severity inflation
- graph component identity confusion
- trust-root replacement
- attestation/signature ambiguity

All adversarial fixtures are designed to be inert. Security tests should inspect, parse, or simulate hostile input without executing a malicious payload on the host.

## Trust and evidence rules

The project treats several distinctions as security invariants:

- an integrity digest is not a cryptographic signature
- a self-consistent trust-root file is not automatically an authentic trust root
- missing evidence is not positive evidence
- a policy exception is not the same thing as a passing policy evaluation
- a relationship inferred from weak identity is not equivalent to a canonical component relationship

## Reproduce locally

Run the full suite:

```bash
pytest
```

Run the focused adversarial coverage:

```bash
pytest tests/test_adversarial_hardening.py -v
```

Run the deterministic golden demo:

```bash
PYTHONPATH=src bash demo/golden-vulnerable-ai/run_demo.sh
```

## What security validation is intended to prove

The goal is not to claim that AI-BOM Inspector is unbreakable. The goal is to make important security properties explicit, reproducible, and regression-tested.

A useful result from an adversarial test is a confirmed bug that can be fixed before an attacker or customer discovers it.
