from __future__ import annotations

import pickletools
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class PickleVMEvent:
    opcode: str
    arg: Optional[str]


@dataclass
class PickleVMTrace:
    path: Optional[Path]
    events: List[PickleVMEvent] = field(default_factory=list)
    globals_referenced: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "path": str(self.path) if self.path else None,
            "events": [e.__dict__ for e in self.events],
            "globals_referenced": self.globals_referenced,
        }


def emulate_pickle(data: bytes, path: Optional[Path] = None, max_events: int = 10000) -> PickleVMTrace:
    """Lightweight, read-only 'pickle VM' that walks pickle opcodes without executing them.

    This prototype uses pickletools.genops to produce a trace of opcodes and
    records GLOBAL / STACK_GLOBAL references. It never imports or executes
    globals, making it safe for a CI-run analysis.
    """
    trace = PickleVMTrace(path=path)
    count = 0
    for opcode, arg, _ in pickletools.genops(data):
        if count >= max_events:
            break
        count += 1
        arg_val = arg if isinstance(arg, str) else None
        trace.events.append(PickleVMEvent(opcode=opcode.name, arg=arg_val))
        if opcode.name in {"GLOBAL", "STACK_GLOBAL"} and isinstance(arg, str):
            trace.globals_referenced.append(arg)
    return trace


def emulate_pickle_file(path: Path, max_events: int = 10000) -> PickleVMTrace:
    data = path.read_bytes()
    return emulate_pickle(data, path=path, max_events=max_events)
