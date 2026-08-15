from pathlib import Path
import pickle

from aibom_inspector.pickle_vm import emulate_pickle, emulate_pickle_file


def test_emulate_pickle_basic(tmp_path: Path):
    data = pickle.dumps({"a": 1, "b": [1,2,3]})
    trace = emulate_pickle(data)
    assert len(trace.events) > 0
    assert isinstance(trace.events[0].opcode, str)


def test_emulate_pickle_with_global_opcode(tmp_path: Path):
    # craft a simple protocol 0 GLOBAL opcode referencing posix system
    raw = b"cposix\nsystem\nq0."
    p = tmp_path / "global.pkl"
    p.write_bytes(raw)
    trace = emulate_pickle_file(p)
    assert any(e.opcode == "GLOBAL" for e in trace.events)
    assert any("posix" in (g or "") for g in trace.globals_referenced)
