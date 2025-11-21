from datetime import datetime, timedelta
from pathlib import Path

from aibom_inspector.model_inspector import STALE_DAYS, parse_model_entry, scan_models_from_file


def test_parse_model_entry_flags_missing_license_and_stale_metadata():
    stale_date = (datetime.utcnow() - timedelta(days=STALE_DAYS + 1)).date().isoformat()
    info = parse_model_entry({"id": "old-model", "source": "huggingface", "last_updated": stale_date})
    descriptions = {issue.message for issue in info.issues}
    assert "Missing license information" in descriptions
    assert "Model metadata is stale" in descriptions


def test_scan_models_from_file_reads_list(tmp_path: Path):
    data = [
        {"id": "gpt2", "source": "huggingface", "license": "mit"},
        {"id": "private-model", "source": "private", "license": "proprietary"},
    ]
    path = tmp_path / "models.json"
    path.write_text(__import__("json").dumps(data))

    models = scan_models_from_file(path)
    assert len(models) == 2
    assert models[0].identifier == "gpt2"
    assert models[1].source == "private"
    assert models[1].issues == []
