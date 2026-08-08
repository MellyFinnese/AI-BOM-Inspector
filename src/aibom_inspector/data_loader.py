from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from .parsers import ParserError, load_json_payload


@lru_cache(maxsize=None)
def _load_packaged_json(resource_name: str) -> dict[str, Any]:
    try:
        payload = resources.files("aibom_inspector.data").joinpath(resource_name).read_text()
    except FileNotFoundError as exc:
        raise ParserError(f"Packaged data resource not found: {resource_name}") from exc

    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ParserError(f"Invalid packaged JSON resource {resource_name}: {exc}") from exc

    if not isinstance(data, dict):
        raise ParserError(f"Packaged JSON resource {resource_name} must contain an object")
    return data


def load_json_data(resource_name: str, override_path: Path | None = None) -> dict[str, Any]:
    if override_path:
        data = load_json_payload(override_path)
        if not isinstance(data, dict):
            raise ParserError(f"JSON data override {override_path} must contain an object")
        return data
    return _load_packaged_json(resource_name)
