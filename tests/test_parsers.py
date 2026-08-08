from __future__ import annotations

import json
from pathlib import Path

import pytest

from aibom_inspector.parsers import ParserError, parse_models_file, parse_policy_file, parse_sbom_file


def test_parse_policy_file_valid(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        "\n".join(
            [
                "min_score: 80",
                "trusted_registries:",
                "  - pypi",
                "exceptions:",
                "  - code: CVE-2024-0001",
                "    subject: demo",
            ]
        )
    )

    policy = parse_policy_file(policy_path)

    assert policy.min_score == 80
    assert policy.trusted_registries == ["pypi"]
    assert policy.exceptions[0].code == "CVE-2024-0001"


def test_parse_policy_file_rejects_unknown_key(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text("min_score: 80\nunknown_field: nope\n")

    with pytest.raises(ParserError):
        parse_policy_file(policy_path)


def test_parse_sbom_file_cyclonedx(tmp_path: Path) -> None:
    sbom_path = tmp_path / "sbom.json"
    sbom_path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [
                    {
                        "name": "requests",
                        "version": "2.32.0",
                    }
                ],
            }
        )
    )

    sbom = parse_sbom_file(sbom_path)

    assert sbom.kind == "cyclonedx"
    assert sbom.payload.components[0].name == "requests"


def test_parse_models_file_list(tmp_path: Path) -> None:
    models_path = tmp_path / "models.json"
    models_path.write_text(json.dumps([{"id": "demo-model", "source": "local"}]))

    data = parse_models_file(models_path)

    assert len(data.models) == 1
    assert data.models[0].id == "demo-model"


def test_parse_sbom_file_invalid(tmp_path: Path) -> None:
    sbom_path = tmp_path / "sbom.json"
    sbom_path.write_text("{not json")

    with pytest.raises(ParserError):
        parse_sbom_file(sbom_path)


def test_parse_policy_file_wraps_schema_errors(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text("min_score: high\n")

    with pytest.raises(ParserError, match="min_score"):
        parse_policy_file(policy_path)


def test_parse_sbom_file_wraps_schema_errors(tmp_path: Path) -> None:
    sbom_path = tmp_path / "sbom.json"
    sbom_path.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [{"version": "1.0"}]}))

    with pytest.raises(ParserError, match="components.0.name"):
        parse_sbom_file(sbom_path)
