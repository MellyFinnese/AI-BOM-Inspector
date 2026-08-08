from __future__ import annotations

import json
from pathlib import Path

import pytest

from aibom_inspector.data_loader import load_json_data
from aibom_inspector.parsers import ParserError


def test_load_json_data_override_validates_json_object(tmp_path: Path) -> None:
    override = tmp_path / "override.json"
    override.write_text(json.dumps(["not", "an", "object"]))

    with pytest.raises(ParserError, match="must contain an object"):
        load_json_data("unused.json", override_path=override)


def test_load_json_data_override_reports_invalid_json(tmp_path: Path) -> None:
    override = tmp_path / "override.json"
    override.write_text("{not json")

    with pytest.raises(ParserError, match="Invalid JSON"):
        load_json_data("unused.json", override_path=override)
