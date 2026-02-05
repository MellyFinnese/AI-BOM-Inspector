from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any


@lru_cache(maxsize=None)
def _load_packaged_json(resource_name: str) -> dict[str, Any]:
    try:
        payload = resources.files("aibom_inspector.data").joinpath(resource_name).read_text()
    except FileNotFoundError:
        return {}
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return {}


def load_json_data(resource_name: str, override_path: Path | None = None) -> dict[str, Any]:
    if override_path:
        try:
            return json.loads(override_path.read_text())
        except Exception:
            return {}
    return _load_packaged_json(resource_name)
