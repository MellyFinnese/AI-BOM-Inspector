from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

from .types import ModelInfo, ModelIssue, apply_license_category_model, categorize_license


STALE_DAYS = 270


KNOWN_MODEL_ADVISORIES = {
    "gpt2": "Known prompt-stealing leakage advisory (demo feed)",
    "meta-llama/Llama-2-7b": "Community advisory: check downstream license terms",
}

MODEL_CVE_FEED = {
    "gpt2": [
        {
            "id": "CVE-2024-0001",
            "summary": "Public advisory: legacy tokenizer path exposed inference prompt leakage",
        }
    ],
    "meta-llama/Llama-2-7b": [
        {
            "id": "CVE-2024-1843",
            "summary": "Research CVE noting unsafe default weights mirror without integrity checks",
        }
    ],
}


def _cache_path(cache_dir: Path, identifier: str) -> Path:
    sanitized = identifier.replace("/", "__")
    return cache_dir / f"{sanitized}.json"


def fetch_model_metadata(identifier: str, cache_dir: Path | None = None, offline: bool = False) -> dict:
    cache = cache_dir or Path(".aibom_cache")
    cache.mkdir(parents=True, exist_ok=True)
    cache_file = _cache_path(cache, identifier)
    if cache_file.exists():
        try:
            return json.loads(cache_file.read_text())
        except Exception:
            pass

    data: Dict[str, str] = {"id": identifier, "source": "huggingface"}

    if offline:
        data["offline"] = True
        cache_file.write_text(json.dumps(data))
        return data

    try:
        try:
            from huggingface_hub import HfApi

            api = HfApi()
            info = api.model_info(identifier)
            data["license"] = getattr(info, "license", None)
            if getattr(info, "lastModified", None):
                data["last_updated"] = info.lastModified.isoformat()
        except ImportError:
            import requests

            response = requests.get(f"https://huggingface.co/api/models/{identifier}", timeout=10)
            if response.status_code == 200:
                payload = response.json()
                data["license"] = payload.get("license")
                if payload.get("lastModified"):
                    data["last_updated"] = payload["lastModified"]
    except Exception:
        data["error"] = "metadata lookup failed"

    cache_file.write_text(json.dumps(data))
    return data


def parse_model_entry(entry: dict) -> ModelInfo:
    identifier = entry.get("id") or entry.get("name") or "unknown-model"
    source = entry.get("source", "local")
    license_name: Optional[str] = entry.get("license")
    last_updated_raw: Optional[str] = entry.get("last_updated")
    last_updated = datetime.fromisoformat(last_updated_raw) if last_updated_raw else None

    issues: List[ModelIssue] = []

    if entry.get("offline"):
        issues.append(
            ModelIssue(
                "[OFFLINE_MODE] Remote metadata lookup skipped",
                severity="low",
                code="OFFLINE_MODE",
            )
        )

    if not license_name:
        issues.append(
            ModelIssue(
                "[UNKNOWN_LICENSE] Missing license information",
                severity="high",
                code="UNKNOWN_LICENSE",
            )
        )
    else:
        category = categorize_license(license_name)
        if category in {"copyleft", "weak_copyleft"}:
            issues.append(
                ModelIssue(
                    "[LICENSE_RISK] Copyleft/reciprocal terms may apply",
                    severity="medium",
                    code="LICENSE_RISK",
                )
            )
        elif category == "unknown":
            issues.append(
                ModelIssue(
                    "[UNKNOWN_LICENSE] License could not be classified",
                    severity="medium",
                    code="UNKNOWN_LICENSE",
                )
            )

    if last_updated and last_updated < datetime.utcnow() - timedelta(days=STALE_DAYS):
        issues.append(
            ModelIssue(
                "[STALE_MODEL] Model metadata is stale",
                severity="medium",
                code="STALE_MODEL",
            )
        )

    if source not in {"huggingface", "local", "private", "openai"}:
        issues.append(
            ModelIssue(
                f"[UNVERIFIED_SOURCE] Unrecognized source '{source}'",
                severity="medium",
                code="UNVERIFIED_SOURCE",
            )
        )

    advisory = KNOWN_MODEL_ADVISORIES.get(identifier)
    if advisory:
        issues.append(
            ModelIssue(
                f"[MODEL_ADVISORY] {advisory}",
                severity="high",
                code="MODEL_ADVISORY",
            )
        )

    model = ModelInfo(
        identifier=identifier,
        source=source,
        license=license_name,
        last_updated=last_updated,
        issues=issues,
    )
    apply_license_category_model(model)
    return model


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


def summarize_models(model_ids: List[str], offline: bool = False) -> List[ModelInfo]:
    models: List[ModelInfo] = []
    for identifier in model_ids:
        metadata = fetch_model_metadata(identifier, offline=offline)
        models.append(parse_model_entry(metadata))
    return models


def enrich_models_with_cves(models: List[ModelInfo]) -> List[ModelInfo]:
    """Cross-check model identifiers against a public CVE-style feed."""

    for model in models:
        advisories = MODEL_CVE_FEED.get(model.identifier, [])
        for advisory in advisories:
            model.issues.append(
                ModelIssue(
                    f"[CVE] {advisory['id']}: {advisory['summary']}",
                    severity="high",
                    code=advisory["id"],
                )
            )

    return models
