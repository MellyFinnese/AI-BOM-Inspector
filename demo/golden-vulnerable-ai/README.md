Golden demo: vulnerable AI project

What is this demo?

A tiny intentionally vulnerable AI project used to demonstrate the end-to-end "killer workflow":

Give AI-BOM Inspector an AI project's SBOM/model artifacts → determine supply-chain risk → explain why → map affected systems → produce evidence → enforce policy.

Files included

- requirements.txt — intentionally outdated dependency (placeholder).
- models.json — includes a legacy .pkl model (no provenance, copyleft license).
- models/vulnerable_model.pkl — empty placeholder file (legacy format triggers policy).
- run_demo.sh — single-command demo to run the scanner and produce a report.

Run the demo

From the repository root:

```bash
bash demo/golden-vulnerable-ai/run_demo.sh
```

Expected outcome (summary):
- The scan flags the legacy .pkl model and fails the policy when `block_legacy_pickles: true`.
- Output includes: what is wrong (legacy .pkl, outdated deps, questionable license), why it matters (policy + integrity risk), what is affected (the model and any services that depend on it), evidence (models.json entry and trace), and suggested remediation (convert to safetensors, update dependency, add provenance).

A short, machine-friendly sample (demo/report.json)

```json
{
  "summary": "Policy violation: legacy pickle model detected",
  "findings": [
    {"id":"PICKLE_DANGEROUS_GLOBALS","severity":"High","path":"demo/golden-vulnerable-ai/models/vulnerable_model.pkl","evidence":"models.json entry; sandbox trace (if enabled)"},
    {"id":"MISSING_PROVENANCE","severity":"Medium","path":"demo/golden-vulnerable-ai/models.json","evidence":"no provenance field"}
  ],
  "policy_action": "block",
  "next_steps": ["Convert model to safetensors","Add provenance metadata","Update or pin vulnerable dependencies"]
}
```

Notes

The demo intentionally uses placeholder package names and an empty .pkl file; replace with real examples when running in your environment.
