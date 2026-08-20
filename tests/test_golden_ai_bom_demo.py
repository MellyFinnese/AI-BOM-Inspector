from __future__ import annotations

import json
from pathlib import Path


def test_golden_demo_model_metadata_exposes_supply_chain_lineage() -> None:
    payload = json.loads(
        Path("demo/golden-vulnerable-ai/models.json").read_text(encoding="utf-8")
    )
    vulnerable = next(item for item in payload["models"] if item["id"] == "vulnerable-model")

    assert vulnerable["version"] == "4"
    assert vulnerable["base_models"] == ["base-model-v2"]
    assert vulnerable["fine_tuned_from"] == ["base-model-v2"]
    assert vulnerable["training_sources"] == ["dataset://transactions/v3"]
    assert len(vulnerable["hashes"]) == 1
    assert vulnerable["deployed_to"] == "demo-app"
