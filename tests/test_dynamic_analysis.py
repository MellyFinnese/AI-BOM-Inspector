from pathlib import Path
import json

from aibom_inspector.dynamic_analysis import parse_pickle_vm_trace


def test_parse_trace_creates_findings(tmp_path: Path):
    trace = {
        "path": "models/bad_model.pkl",
        "events": [{"opcode": "GLOBAL", "arg": "posix system"}],
        "globals_referenced": ["posix system"],
    }
    p = tmp_path / "trace.json"
    p.write_text(json.dumps(trace))

    findings = parse_pickle_vm_trace(p)
    assert len(findings) >= 1
    assert any(f.code == "DYN_PICKLE_GLOBAL" for f in findings)
