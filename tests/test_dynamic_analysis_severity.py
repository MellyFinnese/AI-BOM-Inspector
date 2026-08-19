import json
from pathlib import Path

from aibom_inspector.dynamic_analysis import parse_pickle_vm_trace


def test_benign_global_is_not_classified_as_high_severity(tmp_path: Path):
    # collections.OrderedDict is a completely ordinary, benign global
    # reference that shows up in legitimate pickles all the time. It must
    # not be treated the same as an actually dangerous global.
    trace = {
        "path": "models/benign_model.pkl",
        "events": [{"opcode": "GLOBAL", "arg": "collections OrderedDict"}],
        "globals_referenced": ["collections OrderedDict"],
    }
    p = tmp_path / "trace.json"
    p.write_text(json.dumps(trace))

    findings = parse_pickle_vm_trace(p)

    assert findings, "a referenced global should still produce evidence"
    assert all(f.severity != "high" for f in findings), (
        "a benign global reference must not be classified as high severity"
    )


def test_dangerous_global_is_still_high_severity(tmp_path: Path):
    trace = {
        "path": "models/bad_model.pkl",
        "events": [{"opcode": "GLOBAL", "arg": "posix system"}],
        "globals_referenced": ["posix system"],
    }
    p = tmp_path / "trace.json"
    p.write_text(json.dumps(trace))

    findings = parse_pickle_vm_trace(p)

    assert any(f.severity == "high" and f.code == "DYN_PICKLE_GLOBAL" for f in findings)


def test_mixed_globals_preserve_evidence_for_each(tmp_path: Path):
    trace = {
        "path": "models/mixed_model.pkl",
        "events": [
            {"opcode": "GLOBAL", "arg": "collections OrderedDict"},
            {"opcode": "GLOBAL", "arg": "posix system"},
        ],
        "globals_referenced": ["collections OrderedDict", "posix system"],
    }
    p = tmp_path / "trace.json"
    p.write_text(json.dumps(trace))

    findings = parse_pickle_vm_trace(p)

    # Evidence for both globals must still be present, even though only one
    # is classified as dangerous.
    messages = " ".join(f.message for f in findings)
    assert "OrderedDict" in messages
    assert "system" in messages

    severities = {f.severity for f in findings if "OrderedDict" in f.message}
    assert "high" not in severities

    severities = {f.severity for f in findings if "posix system" in f.message}
    assert "high" in severities
