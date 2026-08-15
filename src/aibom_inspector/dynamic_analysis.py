from __future__ import annotations

import json
from pathlib import Path
from typing import List

from .types_report import IntegrityFinding


def parse_pickle_vm_trace(trace_path: Path) -> List[IntegrityFinding]:
    """Convert a Pickle VM trace JSON into IntegrityFinding items.

    Heuristics:
    - Any GLOBAL or STACK_GLOBAL referencing suspicious modules/names becomes a high-severity finding.
    - If many globals referenced (>10), emit a warning-level finding about broad surface.
    """
    if not trace_path.exists():
        return []
    data = json.loads(trace_path.read_text())
    events = data.get("events", [])
    globals_refs = data.get("globals_referenced", []) or []
    findings: List[IntegrityFinding] = []

    # per-global findings
    for g in globals_refs:
        # g may be like 'posix system' or 'os.system'
        g_text = str(g)
        message = f"Pickle VM referenced global: {g_text}"
        findings.append(IntegrityFinding(kind="pickle-global", path=data.get("path"), message=message, severity="high", code="DYN_PICKLE_GLOBAL"))

    if len(globals_refs) > 10:
        findings.append(IntegrityFinding(kind="pickle-global-summary", path=data.get("path"), message=f"Many globals referenced ({len(globals_refs)}). Possible malicious/complex pickle.", severity="medium", code="DYN_PICKLE_SURFACE"))

    # also include simple event pattern checks
    suspicious_ops = [e for e in events if e.get("opcode") in {"GLOBAL", "STACK_GLOBAL"}]
    if suspicious_ops and not globals_refs:
        findings.append(IntegrityFinding(kind="pickle-opcodes", path=data.get("path"), message=f"Pickle contains {len(suspicious_ops)} GLOBAL opcodes; review required.", severity="medium", code="DYN_PICKLE_OPCODE"))

    return findings
