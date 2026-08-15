from __future__ import annotations

import json
from pathlib import Path
from typing import List

from .dynamic_analysis import parse_pickle_vm_trace
from .types_report import IntegrityFinding


def integrate_sandbox_trace(report_obj, trace_path: Path) -> List[IntegrityFinding]:
    """Load a sandbox trace and append dynamic findings to the report object.

    Returns the list of new integrity findings for downstream use.
    """
    findings = parse_pickle_vm_trace(trace_path)
    if not findings:
        return []
    # report_obj is expected to have integrity_findings attribute (Report)
    existing = getattr(report_obj, "integrity_findings", None)
    if existing is None:
        report_obj.integrity_findings = []
    report_obj.integrity_findings.extend(findings)
    return findings
