from pathlib import Path

from aibom_inspector.model_inspector import _cache_path, parse_model_entry


def test_parse_model_entry_handles_malformed_timestamp():
    info = parse_model_entry(
        {
            "id": "malformed-date",
            "source": "local",
            "license": "mit",
            "last_updated": "not-a-timestamp",
        }
    )
    assert any(issue.code == "MODEL_METADATA_INVALID" for issue in info.issues)
    assert info.last_updated is None


def test_cache_path_cannot_escape_cache_directory(tmp_path: Path):
    cache_dir = tmp_path / "cache"
    result = _cache_path(cache_dir, "..\\escape/../model")
    assert result.parent == cache_dir
    assert result.name.endswith(".json")


def test_artifact_path_must_stay_under_scan_root(tmp_path: Path):
    from aibom_inspector.model_inspector import _analyze_artifacts

    root = tmp_path / "scan"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")

    _, issues, _ = _analyze_artifacts(
        [{"path": str(outside)}], [], scan_root=root
    )
    assert any(issue.code == "MODEL_ARTIFACT_OUTSIDE_ROOT" for issue in issues)
