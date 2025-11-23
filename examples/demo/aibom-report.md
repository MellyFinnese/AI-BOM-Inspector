# AI-BOM Report

Generated at: 2025-11-23T01:15:36.602871
Stack Risk Score: 32/100

## Dependencies

| Name | Version | Source | License | Risk | Issues |
| --- | --- | --- | --- | --- | --- |
| fastapi | ==0.110.0 | requirements.txt | unknown (unknown) | 2 | [UNSTABLE_VERSION] Pre-1.0 release may be unstable (medium) |
| requests | >=2.31.0 | requirements.txt | unknown (unknown) | 2 | [LOOSE_PIN] Version is not strictly pinned (medium) |
| urllib3 | ==2.5.0 | requirements.txt | unknown (unknown) | 0 | None |
| falcon | unversioned | requirements.txt | unknown (unknown) | 3 | [MISSING_PIN] Dependency is not pinned (high) |
| rich | ~=13.7 | pyproject.toml | unknown (unknown) | 0 | None |
| prometheus-client | >=0.20 | pyproject.toml | unknown (unknown) | 4 | [LOOSE_PIN] Version is not strictly pinned (medium); [UNSTABLE_VERSION] Pre-1.0 release may be unstable (medium) |
| node_modules/lodash | 4.17.21 | package-lock.json | unknown (unknown) | 0 | None |
| github.com/pkg/errors | v0.9.1 | go.mod | unknown (unknown) | 0 | None |

## Models

| ID | Source | License | Last Updated | Risk | Issues |
| --- | --- | --- | --- | --- | --- |
| gpt2 | huggingface | mit | 2023-05-01T00:00:00 | 8 | [STALE_MODEL] Model metadata is stale (medium); [MODEL_ADVISORY] Known prompt-stealing leakage advisory (demo feed) (high); [CVE] CVE-2024-0001: Public advisory: legacy tokenizer path exposed inference prompt leakage (high) |
| research-embedder | private | unknown | unknown | 3 | [UNKNOWN_LICENSE] Missing license information (high) |