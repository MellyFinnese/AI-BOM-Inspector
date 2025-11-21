# AI-BOM Report

Generated at: 2025-11-20T14:16:54.878054
Stack Risk Score: 30/100

## Dependencies

| Name | Version | Source | Risk | Issues |
| --- | --- | --- | --- | --- |
| fastapi | ==0.110.0 | requirements.txt | 2 | [UNSTABLE_VERSION] Pre-1.0 release may be unstable |
| requests | >=2.31.0 | requirements.txt | 2 | [LOOSE_PIN] Version is not strictly pinned |
| urllib3 | ==1.25.8 | requirements.txt | 3 | [KNOWN_VULN] CVE-2019-11324: CRLF injection when retrieving HTTP headers |
| falcon | unversioned | requirements.txt | 3 | [MISSING_PIN] Dependency is not pinned |
| rich | ~=13.7 | pyproject.toml | 0 | None |
| prometheus-client | >=0.20 | pyproject.toml | 4 | [LOOSE_PIN] Version is not strictly pinned; [UNSTABLE_VERSION] Pre-1.0 release may be unstable |

## Models

| ID | Source | License | Last Updated | Risk | Issues |
| --- | --- | --- | --- | --- | --- |
| gpt2 | huggingface | mit | 2023-05-01T00:00:00 | 5 | [STALE_MODEL] Model metadata is stale; [MODEL_ADVISORY] Known prompt-stealing leakage advisory (demo feed) |
| research-embedder | private | unknown | unknown | 3 | [UNKNOWN_LICENSE] Missing license information |