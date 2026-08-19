from __future__ import annotations

import json
from pathlib import Path

import pytest

from aibom_inspector.parsers import (
    SAFE_MAX_BYTES,
    ParserError,
    load_json_payload,
    load_yaml_payload,
    parse_models_file,
    parse_policy_file,
    parse_runtime_trace_file,
    parse_sbom_file,
    read_text,
)


def test_read_text_rejects_oversized_file_by_default(tmp_path: Path, monkeypatch) -> None:
    big_path = tmp_path / "big.txt"
    big_path.write_bytes(b"a" * (SAFE_MAX_BYTES + 1))

    # The safety property under test is that an oversized file must never be
    # fully read into memory. Fail loudly if the implementation still calls
    # Path.read_bytes() before the size check.
    original_read_bytes = Path.read_bytes

    def _guarded_read_bytes(self):
        raise AssertionError("read_bytes() was called on an oversized file before the size check")

    monkeypatch.setattr(Path, "read_bytes", _guarded_read_bytes)
    try:
        with pytest.raises(ParserError):
            read_text(big_path)
    finally:
        monkeypatch.setattr(Path, "read_bytes", original_read_bytes)


def test_read_text_allows_file_within_default_limit(tmp_path: Path) -> None:
    small_path = tmp_path / "small.txt"
    small_path.write_text("hello world")

    assert read_text(small_path) == "hello world"


def test_load_json_payload_rejects_oversized_file_by_default(tmp_path: Path) -> None:
    big_path = tmp_path / "big.json"
    # Valid-ish JSON padding that is still over the default safe limit.
    big_path.write_text(json.dumps({"padding": "a" * (SAFE_MAX_BYTES + 1)}))

    with pytest.raises(ParserError):
        load_json_payload(big_path)


def test_load_yaml_payload_rejects_oversized_file_by_default(tmp_path: Path) -> None:
    big_path = tmp_path / "big.yml"
    big_path.write_text("padding: " + "a" * (SAFE_MAX_BYTES + 1))

    with pytest.raises(ParserError):
        load_yaml_payload(big_path)


def test_parse_policy_file_rejects_oversized_file_by_default(tmp_path: Path) -> None:
    big_path = tmp_path / "policy.yml"
    big_path.write_text("min_score: 1\nchange_log:\n  - note: '" + "a" * (SAFE_MAX_BYTES + 1) + "'\n")

    with pytest.raises(ParserError):
        parse_policy_file(big_path)


def test_parse_sbom_file_rejects_oversized_file_by_default(tmp_path: Path) -> None:
    big_path = tmp_path / "sbom.json"
    big_path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [{"name": "pkg", "version": "1.0", "padding": "a" * (SAFE_MAX_BYTES + 1)}],
            }
        )
    )

    with pytest.raises(ParserError):
        parse_sbom_file(big_path)


def test_parse_models_file_rejects_oversized_file_by_default(tmp_path: Path) -> None:
    big_path = tmp_path / "models.json"
    big_path.write_text(json.dumps([{"id": "m", "source": "local", "padding": "a" * (SAFE_MAX_BYTES + 1)}]))

    with pytest.raises(ParserError):
        parse_models_file(big_path)


def test_parse_runtime_trace_file_rejects_oversized_file_by_default(tmp_path: Path) -> None:
    big_path = tmp_path / "trace.json"
    big_path.write_text(json.dumps({"events": [], "padding": "a" * (SAFE_MAX_BYTES + 1)}))

    with pytest.raises(ParserError):
        parse_runtime_trace_file(big_path)


def test_small_inputs_still_parse_within_default_limit(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text("min_score: 80\n")

    policy = parse_policy_file(policy_path)
    assert policy.min_score == 80
