# Benchmark coverage target

The corpus intentionally spans more than happy-path AI calls.

Current categories include provider, agent, tool, MCP, trust-boundary taint, privileged operations, mixed applications, clean negatives, and adversarial negatives. The manifest currently contains 29 labeled cases.

The benchmark should be treated as a regression corpus: when a detector changes, add or adjust a fixture with an explicit reason rather than changing the expected result solely to improve a score.
