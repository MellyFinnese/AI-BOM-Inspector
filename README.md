# AI-BOM Inspector

![AI-BOM Inspector CI](https://img.shields.io/badge/AI--BOM%20Inspector-Scan%20your%20AI%20stack%20in%20CI-blue)

Security-focused AI stack analyzer that builds an AI-BOM (models + deps) and highlights sloppy supply-chain practices across multiple languages.

## What it does
- Parse dependency manifests across Python (`requirements.txt`, `pyproject.toml`), JavaScript (`package.json` / `package-lock.json`), Go (`go.mod`), and Java (`pom.xml`)
- Ingest existing SBOMs (`--sbom-file`) and export CycloneDX or SPDX alongside AI-BOM extensions
- Gather AI model metadata from JSON or explicit Hugging Face IDs (bring your own JSON or HF IDs; no automatic pipeline discovery)
- Apply heuristics for pins, stale models, license posture (permissive vs copyleft vs proprietary vs unknown), and optional CVE lookups via OSV
- Emit JSON, Markdown, HTML, CycloneDX, or SPDX reports with risk breakdowns plus a stub AI summary you can replace with your own LLM integration

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
  - HTML report snapshot: open `examples/demo/aibom-report.html`
  - Markdown rendering snapshot: see `examples/demo/aibom-report.md`
  - Before/after hygiene comparison: `screenshots/before-after.html`

  Small JSON excerpt (full file in `examples/demo/aibom-report.json`):
  ```json
  {
    "stack_risk_score": 30,
    "risk_breakdown": {"unpinned_deps": 3, "unverified_sources": 0, "unknown_licenses": 1, "stale_models": 1},
    "dependencies": [{"name": "urllib3", "issues": ["[KNOWN_VULN] CVE-2019-11324: CRLF injection when retrieving HTTP headers"]}],
    "models": [{"id": "gpt2", "issues": ["[STALE_MODEL] Model metadata is stale", "[MODEL_ADVISORY] Known prompt-stealing leakage advisory (demo feed)"]}]
  }
  ```
- **Screenshots:**
  - HTML report: open `examples/demo/aibom-report.html`
  - Markdown rendering: view `examples/demo/aibom-report.md`
  - Before vs. after: open `screenshots/before-after.html`
- **Sample models file:** `examples/models.sample.json`
- **Sample Markdown report:** `examples/report.sample.md`
- **Example commands:**
  - Only dependency scan with autodetection: `aibom scan --format json`
  - Include models from a file: `aibom scan --models-file examples/models.sample.json --format markdown --output report.md`
  - Specify models inline: `aibom scan --model-id gpt2 --model-id meta-llama/Llama-3-8B --format html`
  - Enrich CVEs during the scan: `aibom scan --with-cves --format json`
  - Include non-Python manifests: `aibom scan --manifest package-lock.json --manifest go.mod --format json`
  - Import an SBOM: `aibom scan --sbom-file path/to/cyclonedx.json --format html --output merged-report.html`
  - Run fully offline (no OSV/HF calls): `aibom scan --offline --format markdown`
  - Export CycloneDX: `aibom scan --format cyclonedx --sbom-output aibom-cyclonedx.json`
  - Fail CI if risk > 70: `aibom scan --fail-on-score 70 --format html`
  - Quick comparison of two runs: `aibom diff aibom-report-old.json aibom-report-new.json`

## Heuristics & Risk Signals
AI-BOM Inspector ships with lightweight, explainable checks that map to common AI supply-chain issues:

| Code | What it means | Severity |
| --- | --- | --- |
| `MISSING_PIN` | Dependency version not pinned with `==`/`~=` | High |
| `LOOSE_PIN` | Dependency uses a range (`>=`, `<=`, etc.) | Medium |
| `UNSTABLE_VERSION` | Pre-1.0 releases that may churn | Medium |
| `KNOWN_VULN` / `CVE` | Known vulnerable versions (built-in heuristics + optional OSV lookup; recommends safer versions when known) | High |
| `LICENSE_RISK` | Copyleft / reciprocal terms detected for a model | Medium |
| `UNKNOWN_LICENSE` | Model or SBOM component lacks license metadata | High |
| `STALE_MODEL` | Model metadata older than ~9 months | Medium |
| `UNVERIFIED_SOURCE` | Non-standard model source value | Medium |
| `MODEL_ADVISORY` | Model flagged by a published advisory | High |

The report shows a `stack_risk_score` (0–100, higher is safer) and a `risk_breakdown` capturing unpinned deps, unverified sources, unknown licenses, stale models, and CVE hits. Tune the scoring with `--risk-max-score`, per-severity `--risk-penalty-*` flags, and governance/CVE penalties so teams can calibrate what “red” means for them.

### Before vs. after hardening

| Scenario | Risk score | Signals |
| --- | --- | --- |
| **Messy AI stack** | 48/100 | Unpinned `package-lock.json`, unknown model license, stale model metadata |
| **Hardened AI stack** | 88/100 | All deps pinned, permissive licenses, fresh model metadata, no advisories |

### Example: scanning a real project
```bash
aibom scan --requirements requirements.txt --models-file models.json --with-cves --format html --output report.html \
  --risk-penalty-high 10 --risk-penalty-medium 5 --risk-penalty-low 2
```
Pair it with `aibom diff report-old.json report-new.json` to highlight PR drift, or run in CI with `--fail-on-score 70`.


## Testing and CI
- Run unit tests: `pytest`
- GitHub Action: `.github/workflows/aibom-inspector-action.yml` uses the bundled composite action to scan PRs and post a risk comment.
- CI guardrails: use `--fail-on-score <threshold>` to block merges when the AI risk score drops below your bar.

## Security, governance, and contributions
- See `SECURITY.md` for how to report vulnerabilities.
- See `CODE_OF_CONDUCT.md` for community standards.
- See `CONTRIBUTING.md` for development conventions and how to propose changes.
- `CHANGELOG.md` tracks notable updates.
