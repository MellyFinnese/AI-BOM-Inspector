from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

from .types import ModelInfo, ModelIssue


STALE_DAYS = 365


def parse_model_entry(entry: dict) -> ModelInfo:
    identifier = entry.get("id") or entry.get("name") or "unknown-model"
    source = entry.get("source", "local")
    license_name: Optional[str] = entry.get("license")
    last_updated_raw: Optional[str] = entry.get("last_updated")
    last_updated = datetime.fromisoformat(last_updated_raw) if last_updated_raw else None

    issues: List[ModelIssue] = []

    if not license_name:
        issues.append(ModelIssue("Missing license information", severity="high"))

    if last_updated and last_updated < datetime.utcnow() - timedelta(days=STALE_DAYS):
        issues.append(ModelIssue("Model metadata is stale", severity="medium"))

    if source not in {"huggingface", "local", "private"}:
        issues.append(ModelIssue(f"Unrecognized source '{source}'", severity="medium"))

    return ModelInfo(
        identifier=identifier,
        source=source,
        license=license_name,
        last_updated=last_updated,
        issues=issues,
    )


def scan_models_from_file(path: Path) -> List[ModelInfo]:
    if not path or not path.exists():
        return []

    data = json.loads(path.read_text())
    entries = data if isinstance(data, list) else data.get("models", [])

    models: List[ModelInfo] = []
    for entry in entries:
        if isinstance(entry, dict):
            models.append(parse_model_entry(entry))
    return models


def summarize_models(model_ids: List[str]) -> List[ModelInfo]:
    models: List[ModelInfo] = []
    for identifier in model_ids:
        models.append(
            ModelInfo(
                identifier=identifier,
                source="huggingface",
                license=None,
                last_updated=None,
                issues=[ModelIssue("Metadata lookup not provided", severity="medium")],
            )
        )
    return models
