# Quickstart

Follow these steps to run AI-BOM Inspector locally in offline mode, then layer in optional enrichment.

## Install

```bash
pip install -e .[dev]
# Or use pinned dependencies for reproducible runs:
pip install -r requirements.txt
```

## Create a models file

Add model metadata when you want models scanned alongside dependencies. A ready-to-use sample lives at `examples/models.sample.json`:

```json
[
  {"id": "gpt2", "source": "huggingface", "license": "mit", "last_updated": "2024-01-01"},
  {"id": "custom-embedder", "source": "private"}
]
```

## Run your first scan

```bash
# Auto-detect manifests (offline by default)
aibom scan --models-file examples/models.sample.json --format markdown --output report.md

# Allow network lookups when needed
aibom scan --online --with-cves --format json --output report.json
```

Add `--require-input` to fail early when no manifests or SBOM files are found.

## Export SBOMs

Use existing SBOMs as input or export new ones during a scan:

```bash
# Import a CycloneDX SBOM and render HTML
aibom scan --sbom-file examples/demo/aibom-report.json --format html --output merged-report.html

# Export CycloneDX while scanning
aibom scan --format cyclonedx --sbom-output aibom-cyclonedx.json
```

## Enforce in CI

- Reuse the prebuilt workflow in `.github/workflows/scan-pr.yml` to comment on pull requests.
- Add `--fail-on-score` to make CI fail when the stack score dips below your threshold (e.g., `--fail-on-score 70`).
