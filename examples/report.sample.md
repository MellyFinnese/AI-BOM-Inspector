# AI-BOM Inspector Report (sample)

## Overview
- **Dependencies scanned:** requirements.txt, pyproject.toml
- **Models scanned:** 3 entries (huggingface/local)
- **Overall risk score:** 21

## Dependency findings
- click==8.1.7 — no issues detected
- jinja2==3.1.4 — no issues detected
- requests>=2.0.0 — Version is not strictly pinned (medium)

## Model findings
- gpt2 (huggingface) — last updated 2024-01-01 — no issues detected
- custom-embedder (private) — Missing license information (high)
- research-demo (local) — Missing license information (high)

> Generated with: `aibom scan --models-file examples/models.sample.json --format markdown`
