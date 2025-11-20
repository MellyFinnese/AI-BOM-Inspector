# AI-BOM Inspector

Security-focused AI stack analyzer that builds an AI-BOM (models + deps) and highlights real supply-chain risk.

## What it does
- Parse Python dependencies from `requirements.txt` and `pyproject.toml`
- Gather AI model metadata from a JSON file or a list of HuggingFace IDs
- Apply quick heuristics for missing pins, unstable versions, stale models, and unknown licenses
- Emit JSON, Markdown, or single-page HTML reports
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

## Examples
- **Sample models file:** `examples/models.sample.json`
- **Sample Markdown report:** `examples/report.sample.md`
- **Example commands:**
  - Only dependency scan with autodetection: `aibom scan --format json`
  - Include models from a file: `aibom scan --models-file examples/models.sample.json --format markdown --output report.md`
  - Specify models inline: `aibom scan --model-id gpt2 --model-id meta-llama/Llama-3-8B --format html`

## Testing and CI
- Run unit tests: `pytest`
- GitHub Actions runs formatting-free CI on pushes and pull requests via `.github/workflows/ci.yml`.

## Security, governance, and contributions
- See `SECURITY.md` for how to report vulnerabilities.
- See `CODE_OF_CONDUCT.md` for community standards.
- See `CONTRIBUTING.md` for development conventions and how to propose changes.
- `CHANGELOG.md` tracks notable updates.
