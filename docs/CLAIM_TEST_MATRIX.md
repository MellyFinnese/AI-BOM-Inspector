# Claim → Test → Evidence Matrix

This file maps high-level product claims to the tests that provide proof and the evidence artifacts produced.

| Claim | Proof (test) | Evidence produced |
| --- | --- | --- |
| Risk scoring is deterministic | tests/test_risk_determinism.py | repeated-input reports, score parity artifacts |
| Graph enrichment does not change deterministic risk | tests/test_graph_score_parity.py | baseline vs enriched report diff |
| Policies can block deployments | tests/test_golden_demo.py | demo/report.json with policy_action=block |
| Evidence is tamper-evident | tests/test_attestation_sigstore.py | attestation JSON, .sha256 files |
| Model artifacts are inspected safely | tests/test_pickle_vm.py, tests/test_pickle_sandbox_runner.py | sandbox traces (JSON) |
| SBOM outputs are standards-compliant | tests/test_cyclonedx_schema.py, tests/test_spdx_rich.py | CycloneDX JSON, SPDX tag-value outputs |

Add tests to the left column as the suite grows; naming tests after the claim makes the mapping explicit and reviewable.