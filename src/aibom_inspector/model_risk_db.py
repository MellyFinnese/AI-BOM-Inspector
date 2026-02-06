from __future__ import annotations

from functools import lru_cache
import hashlib
import json
from pathlib import Path
from typing import Any

from .data_loader import load_json_data


_MODEL_ADVISORY_DB_PATH: Path | None = None
_MODEL_HASH_DB_PATH: Path | None = None
_THREAT_TAXONOMY_DB_PATH: Path | None = None
_TRAINING_SOURCE_DB_PATH: Path | None = None


def set_model_advisory_db_path(path: Path | None) -> None:
    global _MODEL_ADVISORY_DB_PATH
    _MODEL_ADVISORY_DB_PATH = path
    load_model_advisory_db.cache_clear()


def set_model_hash_db_path(path: Path | None) -> None:
    global _MODEL_HASH_DB_PATH
    _MODEL_HASH_DB_PATH = path
    load_model_hash_db.cache_clear()


def set_threat_taxonomy_db_path(path: Path | None) -> None:
    global _THREAT_TAXONOMY_DB_PATH
    _THREAT_TAXONOMY_DB_PATH = path
    load_threat_taxonomy_db.cache_clear()


def set_training_source_db_path(path: Path | None) -> None:
    global _TRAINING_SOURCE_DB_PATH
    _TRAINING_SOURCE_DB_PATH = path
    load_training_source_db.cache_clear()


@lru_cache(maxsize=None)
def load_model_advisory_db() -> dict[str, Any]:
    return load_json_data("model_vulnerability_db.json", _MODEL_ADVISORY_DB_PATH)


@lru_cache(maxsize=None)
def load_model_hash_db() -> dict[str, Any]:
    return load_json_data("model_hash_reputation.json", _MODEL_HASH_DB_PATH)


@lru_cache(maxsize=None)
def load_threat_taxonomy_db() -> dict[str, Any]:
    return load_json_data("ai_threat_taxonomy.json", _THREAT_TAXONOMY_DB_PATH)


@lru_cache(maxsize=None)
def load_training_source_db() -> dict[str, Any]:
    return load_json_data("training_source_fingerprints.json", _TRAINING_SOURCE_DB_PATH)


def get_intel_versions() -> dict[str, dict[str, str | None]]:
    advisory = load_model_advisory_db()
    hashes = load_model_hash_db()
    taxonomy = load_threat_taxonomy_db()
    training = load_training_source_db()
    return {
        "model_advisory_db": _version_hash(advisory),
        "model_hash_db": _version_hash(hashes),
        "threat_taxonomy_db": _version_hash(taxonomy),
        "training_source_db": _version_hash(training),
    }


def _version_hash(payload: dict[str, Any]) -> dict[str, str | None]:
    version = str(payload.get("version")) if payload.get("version") is not None else None
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    return {"version": version, "sha256": digest}
