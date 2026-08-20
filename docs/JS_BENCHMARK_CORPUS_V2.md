# JavaScript / TypeScript benchmark corpus v2

This corpus validates static AI usage detection with positive, clean-negative, and adversarial-negative fixtures.

Coverage includes providers, model calls, agents, tools, MCP, trust boundaries, privileged operations, CommonJS, and lookalike text.

Run:

```bash
PYTHONPATH=src python -m aibom_inspector benchmark benchmarks/javascript/manifest.json
```
