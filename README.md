# AI-BOM Inspector

Security-focused AI stack analyzer that builds an AI-BOM (models + deps) and highlights real supply-chain risk.

## What it does
- Parse Python dependencies from `requirements.txt` and `pyproject.toml`
- Gather AI model metadata from a JSON file or a list of HuggingFace IDs
- Apply quick heuristics for missing pins, unstable versions, stale models, and unknown licenses
- Emit JSON, Markdown, or single-page HTML reports
- Stub AI summary output you can replace with your own LLM integration

## Getting started
1. Install the package locally:
   ```bash
   pip install -e .
   ```
2. Create a `models.json` file if you want to include model metadata:
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

Use `aibom scan --help` for the full list of options.
