# Credibility pack

Curated repos, SBOMs, and expected outcomes you can use to validate heuristics and policy gates.

## How to run the pack
- Clone or fetch the listed repos (shallow clone is fine) alongside AI-BOM Inspector.
- Run `aibom scan --format json --output out.json --offline --discover-stack` from the repo root.
- Compare the output against the scoreboard below; minor drift is expected when dependencies move, but the issue mix should stay stable.

## Sample SBOMs (drop-in demos)
- `sboms/langchain-sample.cdx.json`: trimmed CycloneDX excerpt from `langchain-ai/langchain` with OpenAI + HF references.
- `sboms/transformers-sample.cdx.json`: small SBOM slice from `huggingface/transformers` highlighting `from_pretrained` usage.
- `sboms/llamaindex-sample.cdx.json`: focused on `llama-index` with Bedrock + Anthropic hooks.

## Scoreboard (expected signals)

| Repo | Expected issues | CVE/advisory hits | License risks | Notes |
| --- | --- | --- | --- | --- |
| langchain-ai/langchain | 6–8 pins/warnings | 0–1 (OSV enrichment off by default) | 1 (third-party model license unknown) | Agents + toolchains auto-discovered; policy should warn on unknown model sources. |
| openai/openai-python | 2–3 pins/warnings | 0 | 0 | Provider SDK detection should tag `openai` provider and surface `OPENAI_API_KEY` env var clues. |
| anthropic/anthropic-sdk-python | 2–3 pins/warnings | 0 | 0 | Detect `claude-*` model references and Anthropic env vars. |
| huggingface/transformers | 5–7 pins/warnings | 0–1 (older torch versions) | 1 (unknown license for sample model) | `from_pretrained` model IDs should auto-populate without `models.json`. |
| llama-index-team/llamaindex | 6–9 pins/warnings | 1 (if OSV enabled for `fastapi`/`pydantic`) | 1–2 | Bedrock + Anthropic providers should be inferred from dependencies and configs. |
| langchain-ai/langgraph | 4–6 pins/warnings | 0 | 0 | Agent framework node expected in stack graph. |
| openai/evals | 4–5 pins/warnings | 1–2 (eval extras) | 1 | Model IDs are often inline; auto-discovery should pick up OpenAI models from configs. |
| run-llama/llama_index_examples | 5–6 pins/warnings | 0–1 | 1 | Mixed Hugging Face + local model IDs; `UNVERIFIED_SOURCE` should appear for custom paths. |
| pytorch/examples | 3–4 pins/warnings | 0–1 | 0–1 | Model hosts detected via `torch` dependency; model IDs inferred from training scripts. |
| tensorflow/models | 4–6 pins/warnings | 0–1 | 0–1 | TensorFlow provider should register as `ModelHost`; expect `MODEL_ID` env var hits in configs. |
| ray-project/ray-llm-examples | 5–7 pins/warnings | 0–1 | 1 | Mix of OpenAI/Anthropic/HF providers; expect multiple provider nodes in stack snapshot. |
| PrefectHQ/marvin | 3–5 pins/warnings | 0 | 1 | LLM config defaults should yield model ID discoveries without manual input. |

## What to look for
- Stack discovery graph should include providers (OpenAI/Anthropic/Hugging Face), model hosts (Transformers/Torch/TensorFlow), and any MCP/tool files with write scopes.
- SARIF output should carry `helpUri` links back to `POLICY`/`POLICY_COOKBOOK` for each rule.
- Policy failures should prefer graph guardrails over ambiguous errors (e.g., "unpinned model in prod" vs. "missing metadata").

## Updating the pack
- Refresh SBOM slices when upstream releases introduce new dependencies.
- Keep counts loose (ranges above) to allow minor version bumps without false negatives.
- If you add a repo, include the detection hook you expect (provider env var, `from_pretrained`, Bedrock config, etc.).
