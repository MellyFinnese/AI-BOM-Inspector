# AI-BOM Inspector

Security-focused AI stack analyzer that builds an AI-BOM (models + deps) and highlights sloppy supply-chain practices across multiple languages.

## What it does
- Parse dependency manifests across Python (`requirements.txt`, `pyproject.toml`), JavaScript (`package.json` / `package-lock.json`), Go (`go.mod`), and Java (`pom.xml`)
- Gather AI model metadata from JSON or explicit Hugging Face IDs (bring your own JSON or HF IDs; no automatic pipeline discovery)
- Apply lightweight heuristics to flag missing pins, loose ranges, unstable versions, stale models, and unknown model licenses (heuristics only; no CVE feeds yet)
- Emit JSON, Markdown, and HTML reports with an AI-BOM extension for model metadata
- Stub AI summary output you can replace with your own LLM integration

## Getting started
1. Install the package locally (editable install for development):
   ```bash
   pip install -e .[dev]
   ```
   For reproducible CI or audits, install the pinned dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Create a `models.json` file if you want to include model metadata. A ready-to-use sample lives in `examples/models.sample.json`:
   ```json
   [
     {"id": "gpt2", "source": "huggingface", "license": "mit", "last_updated": "2024-01-01"},
     {"id": "custom-embedder", "source": "private"}
   ]
   ```
3. Run the scanner (auto-detects dependency files when present):
   ```bash
   aibom scan --models-file models.json --format html --output report.html
   ```
   Run `aibom scan --help` for the full list of options and supported formats.

### Who is this for?
- AppSec and security engineers who want CI/CD-friendly AI-BOMs without shipping code to a third party
- MLOps/platform teams who need model metadata (license, freshness, advisories) next to dependencies
- Builders who want tweakable, explainable rules instead of black-box scanners

### Why this vs. Snyk & friends?
- **Small, OSS, local-first**: zero data leaves your laptop or CI box.
- **AI-stack aware**: treats models as first-class assets instead of opaque blobs.
- **Customizable rules**: heuristics are readable Python, not black-box policies.

## Examples
- **End-to-end demo** (`examples/demo/`): tiny app with `requirements.txt`, `pyproject.toml`, `package-lock.json`, `go.mod`, `models.json`, and generated `aibom-report.json/md/html`.

  Small JSON excerpt (full file in `examples/demo/aibom-report.json`):
  ```json
  {
    "stack_risk_score": 52,
    "risk_breakdown": {"unpinned_deps": 3, "unverified_sources": 1, "unknown_licenses": 1, "stale_models": 0},
    "dependencies": [{"name": "lodash", "issues": ["[LOOSE_PIN] Version is not strictly pinned"]}],
    "models": [{"id": "gpt2", "issues": ["[MODEL_ADVISORY] Known prompt-stealing leakage advisory (demo feed)"]}]
  }
  ```
- **Sample models file:** `examples/models.sample.json`
- **Sample Markdown report:** `examples/report.sample.md`
- **Example commands:**
  - Only dependency scan with autodetection: `aibom scan --format json`
  - Include models from a file: `aibom scan --models-file examples/models.sample.json --format markdown --output report.md`
  - Specify models inline: `aibom scan --model-id gpt2 --model-id meta-llama/Llama-3-8B --format html`
  - Include non-Python manifests: `aibom scan --manifest package-lock.json --manifest go.mod --format json`
  - Fail CI if risk > 70: `aibom scan --fail-on-score 70 --format html`

## Heuristics & Risk Signals
AI-BOM Inspector ships with lightweight, explainable checks that map to common AI supply-chain issues:

| Code | What it means | Severity |
| --- | --- | --- |
| `MISSING_PIN` | Dependency version not pinned with `==`/`~=` | High |
| `LOOSE_PIN` | Dependency uses a range (`>=`, `<=`, etc.) | Medium |
| `UNSTABLE_VERSION` | Pre-1.0 releases that may churn | Medium |
| `KNOWN_VULN` | Matches a known-bad version (e.g., urllib3 1.25.8) | High |
| `UNKNOWN_LICENSE` | Model lacks license metadata | High |
| `STALE_MODEL` | Model metadata older than ~9 months | Medium |
| `UNVERIFIED_SOURCE` | Non-standard model source value | Medium |
| `MODEL_ADVISORY` | Model flagged by a published advisory | High |

The report shows a `stack_risk_score` (0–100, higher is safer) and a `risk_breakdown` capturing unpinned deps, unverified sources, unknown licenses, and stale models.

### Example: scanning a real project
```bash
aibom scan --requirements requirements.txt --models-file models.json --format html --output report.html
```
Pair it with `aibom diff report-old.json report-new.json` to highlight PR drift, or run in CI with `--fail-on-score 70`.

### Planned killer feature
Cross-check models and dependencies against public CVE feeds with a customizable 0–100 AI risk score and HTML visualization (table + severity badges). (Planned, not implemented.)

The report shows a `stack_risk_score` (0–100, higher is safer) derived from the number and severity of these findings. A red badge highlights when high-risk flags dominate (e.g., missing pins + unverified sources). Sample Markdown and HTML outputs in `examples/demo/` show how the signals render alongside dependency and model tables.

## Testing and CI
- Run unit tests: `pytest`
- CI examples and GitHub Action templates are not bundled yet; run locally or wire into your own workflows.

## Security, governance, and contributions
- See `SECURITY.md` for how to report vulnerabilities.
- See `CODE_OF_CONDUCT.md` for community standards.
- See `CONTRIBUTING.md` for development conventions and how to propose changes.
- `CHANGELOG.md` tracks notable updates.
