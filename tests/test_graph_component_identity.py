import json
from pathlib import Path

from click.testing import CliRunner

from aibom_inspector.cli import main


def test_impact_purl_identity_avoids_cross_ecosystem_collision(tmp_path: Path):
    """A model depending on an unrelated pypi 'lodash' must not be flagged as
    impacted by a CVE in the npm 'lodash' package just because the normalized
    package-name suffix happens to match.
    """
    runner = CliRunner()
    report = {
        "generated_at": "2026-01-01T00:00:00",
        "dependencies": [
            {
                "name": "lodash",
                "version": "4.17.20",
                "source": "npm",
                "purl": "pkg:npm/lodash@4.17.20",
                "issue_details": [
                    {"message": "[CVE] CVE-TEST-2: prototype pollution", "severity": "high", "code": "CVE-TEST-2"}
                ],
            }
        ],
        "models": [
            {
                "id": "model-npm-consumer",
                "supporting_dependencies": [
                    {"name": "lodash", "purl": "pkg:npm/lodash@4.17.20"},
                ],
                "deployed_to": "app-npm",
            },
            {
                "id": "model-pypi-consumer",
                # Same normalized suffix ("lodash") but a completely different,
                # unrelated ecosystem/package via purl.
                "supporting_dependencies": [
                    {"name": "lodash", "purl": "pkg:pypi/lodash@1.0.0"},
                ],
                "deployed_to": "app-pypi",
            },
        ],
        "applications": [
            {"name": "app-npm", "owner": "alice"},
            {"name": "app-pypi", "owner": "bob"},
        ],
    }

    p = tmp_path / "report.json"
    p.write_text(json.dumps(report))

    result = runner.invoke(main, ["graph", "impact", "--report", str(p), "CVE-TEST-2"])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "Models: 1" in out
    assert "model-npm-consumer" in out
    assert "model-pypi-consumer" not in out
    assert "app-npm" in out
    assert "app-pypi" not in out


def test_impact_falls_back_to_name_suffix_when_no_canonical_identity(tmp_path: Path):
    """Existing behaviour is preserved when no purl/ecosystem data is present
    anywhere in the report: matching falls back to the normalized name.
    """
    runner = CliRunner()
    report = {
        "generated_at": "2026-01-01T00:00:00",
        "dependencies": [
            {
                "name": "vuln_pkg",
                "version": "1.2.3",
                "source": "requirements.txt",
                "issue_details": [
                    {"message": "[CVE] CVE-TEST-3: example vulnerability", "severity": "high", "code": "CVE-TEST-3"}
                ],
            }
        ],
        "models": [
            {
                "id": "model-alpha",
                "supporting_dependencies": ["vuln_pkg"],
                "deployed_to": "app-1",
            },
        ],
        "applications": [{"name": "app-1", "owner": "alice"}],
    }

    p = tmp_path / "report.json"
    p.write_text(json.dumps(report))

    result = runner.invoke(main, ["graph", "impact", "--report", str(p), "CVE-TEST-3"])
    assert result.exit_code == 0, result.output
    assert "model-alpha" in result.output
