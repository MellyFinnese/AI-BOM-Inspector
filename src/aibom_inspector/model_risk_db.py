from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from .data_loader import load_json_data


_MODEL_ADVISORY_DB_PATH: Path | None = None
_MODEL_HASH_DB_PATH: Path | None = None
_THREAT_TAXONOMY_DB_PATH: Path | None = None


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


@lru_cache(maxsize=None)
def load_model_advisory_db() -> dict[str, Any]:
    return load_json_data("model_vulnerability_db.json", _MODEL_ADVISORY_DB_PATH)


@lru_cache(maxsize=None)
def load_model_hash_db() -> dict[str, Any]:
    return load_json_data("model_hash_reputation.json", _MODEL_HASH_DB_PATH)


@lru_cache(maxsize=None)
def load_threat_taxonomy_db() -> dict[str, Any]:
    return load_json_data("ai_threat_taxonomy.json", _THREAT_TAXONOMY_DB_PATH)
