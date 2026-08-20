from __future__ import annotations

from pathlib import Path

from aibom_inspector.audit_log import append_audit_log, build_audit_entry, verify_audit_log


def test_audit_chain_detects_tampering(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    append_audit_log(
        path,
        build_audit_entry(
            action="scan", actor="alice", report_path=None, report_sha256="abc", attestation_path=None, policy_path=None, approvals=[]
        ),
    )
    append_audit_log(
        path,
        build_audit_entry(
            action="export", actor="alice", report_path=None, report_sha256="def", attestation_path=None, policy_path=None, approvals=[]
        ),
    )
    assert verify_audit_log(path) == []

    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = lines[0].replace('"action":"scan"', '"action":"tampered"')
    path.write_text("\n".join([tampered, lines[1]]) + "\n", encoding="utf-8")
    assert verify_audit_log(path)
