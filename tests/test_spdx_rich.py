import json
from pathlib import Path

from aibom_inspector.exporters import export_spdx, export_spdx_tagvalue


def _sample_report(tmp_path: Path) -> Path:
    report = {
        "stack_risk_score": 55,
        "executive_summary": "SPDX test",
        "dependencies": [
            {"name": "lib-a", "version": "1.2.3", "purl": "pkg:pypi/lib-a@1.2.3", "licenses": ["Apache-2.0"]},
            {"name": "lib-b", "version": "0.0.1", "purl": "pkg:pypi/lib-b@0.0.1", "licenses": ["MIT"], "depends_on": ["lib-a"]},
        ],
        "files": [{"path": "models/model.pt", "license": "NOASSERTION"}],
    }
    p = tmp_path / "report.json"
    p.write_text(json.dumps(report))
    return p


def test_spdx_json_and_tagvalue(tmp_path: Path):
    report = _sample_report(tmp_path)
    out = tmp_path / "spdx.json"
    tv = tmp_path / "spdx.tv"

    export_spdx(report, out)
    export_spdx_tagvalue(report, tv)

    assert out.exists()
    data = json.loads(out.read_text())
    assert data.get("spdxVersion") == "SPDX-3.0"
    assert isinstance(data.get("packages"), list)
    assert isinstance(data.get("files"), list)

    assert tv.exists()
    tv_text = tv.read_text()
    assert "SPDXVersion" in tv_text
    assert "PackageName: lib-a" in tv_text
