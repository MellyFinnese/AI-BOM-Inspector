import json
from pathlib import Path

import jsonschema

from aibom_inspector.exporters import export_cyclonedx


def _sample_report_with_vulns(tmp_path: Path) -> Path:
    report = {
        "stack_risk_score": 99,
        "executive_summary": "Sample with vulnerabilities",
        "dependencies": [
            {"name": "requests", "version": "2.34.2", "purl": "pkg:pypi/requests@2.34.2", "licenses": ["Apache-2.0"]},
            {"name": "vuln-lib", "version": "0.1.0", "purl": "pkg:pypi/vuln-lib@0.1.0", "licenses": ["MIT"]},
        ],
        "vulnerabilities": [
            {"id": "CVE-2026-0001", "ratings": [{"score": 9.8, "method": "CVSSv3"}], "affects": ["vuln-lib"], "references": [{"url": "https://example.com/advisory"}]}
        ],
    }
    p = tmp_path / "report.json"
    p.write_text(json.dumps(report))
    return p


def test_cyclonedx_against_schema(tmp_path: Path):
    report_path = _sample_report_with_vulns(tmp_path)
    out = tmp_path / "bom-cdx.json"
    export_cyclonedx(report_path, out)

    assert out.exists()
    data = json.loads(out.read_text())

    schema = json.loads((Path(__file__).parents[1] / "schemas" / "cyclonedx-1.7.schema.json").read_text())
    # should not raise
    jsonschema.validate(instance=data, schema=schema)

    # Basic expectations
    assert data.get("bomFormat") == "CycloneDX"
    assert data.get("specVersion") == "1.7"
    assert isinstance(data.get("components"), list)
    assert isinstance(data.get("vulnerabilities"), list)
