# AI-BOM Report

Generated at: 2025-11-21T03:04:39.515784
Stack Risk Score: 30/100

## Dependencies

| Name | Version | Source | License | Risk | Issues |
| --- | --- | --- | --- | --- | --- |
| fastapi | ==0.110.0 | requirements.txt | unknown (unknown) | 2 | [UNSTABLE_VERSION] Pre-1.0 release may be unstable |
| requests | >=2.31.0 | requirements.txt | unknown (unknown) | 2 | [LOOSE_PIN] Version is not strictly pinned |
| urllib3 | ==1.25.8 | requirements.txt | unknown (unknown) | 3 | [KNOWN_VULN] CVE-2019-11324: CRLF injection when retrieving HTTP headers |
| falcon | unversioned | requirements.txt | unknown (unknown) | 3 | [MISSING_PIN] Dependency is not pinned |
| rich | ~=13.7 | pyproject.toml | unknown (unknown) | 0 | None |
| prometheus-client | >=0.20 | pyproject.toml | unknown (unknown) | 4 | [LOOSE_PIN] Version is not strictly pinned; [UNSTABLE_VERSION] Pre-1.0 release may be unstable |
| node_modules/lodash | 4.17.21 | package-lock.json | unknown (unknown) | 0 | None |
| github.com/pkg/errors | v0.9.1 | go.mod | unknown (unknown) | 0 | None |

## Models

| ID | Source | License | Last Updated | Risk | Issues |
| --- | --- | --- | --- | --- | --- |
| gpt2 | huggingface | mit | 2023-05-01T00:00:00 | 5 | [STALE_MODEL] Model metadata is stale; [MODEL_ADVISORY] Known prompt-stealing leakage advisory (demo feed) |
| research-embedder | private | unknown | unknown | 3 | [UNKNOWN_LICENSE] Missing license information |