from __future__ import annotations

from pathlib import Path

from aibom_inspector import bidi_guard


def test_find_bidi_detects_control_characters():
    text = "safe text\u202esurprise"
    assert bidi_guard.find_bidi(text) == {"\u202e"}


def test_scan_paths_reports_files(tmp_path: Path):
    clean = tmp_path / "clean.txt"
    clean.write_text("hello")

    suspect = tmp_path / "suspect.txt"
    suspect.write_text("prefix\u2069suffix")

    findings = bidi_guard.scan_paths([clean, suspect])
    assert clean not in findings
    assert findings[suspect] == {"\u2069"}
