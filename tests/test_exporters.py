import json
from pathlib import Path

from aibom_inspector.exporters import export_cyclonedx, export_spdx


def _sample_report(tmp_path: Path) -> Path:
    report = {
        "stack_risk_score": 42,
        "executive_summary": "Test summary",
        "dependencies": [
            {"name": "requests", "version": "2.34.2", "purl": "pkg:pypi/requests@2.34.2", "licenses": ["Apache-2.0"]},
            {"name": "example-lib", "version": "1.0.0", "license": "MIT"},
        ],
    }
    p = tmp_path / "report.json"
    p.write_text(json.dumps(report))
    return p


def test_export_cyclonedx_and_spdx(tmp_path: Path):
    report_path = _sample_report(tmp_path)
    cdx_out = tmp_path / "bom-cdx.json"
    spdx_out = tmp_path / "bom-spdx.json"

    export_cyclonedx(report_path, cdx_out)
    export_spdx(report_path, spdx_out)

    assert cdx_out.exists()
    cdx = json.loads(cdx_out.read_text())
    assert cdx.get("bomFormat") == "CycloneDX"
    assert cdx.get("specVersion") == "1.7"
    assert isinstance(cdx.get("components"), list)

    assert spdx_out.exists()
    spdx = json.loads(spdx_out.read_text())
    assert spdx.get("spdxVersion") == "SPDX-3.0"
    assert isinstance(spdx.get("packages"), list)
