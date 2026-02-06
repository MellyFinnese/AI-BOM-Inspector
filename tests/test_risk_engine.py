from __future__ import annotations

import json
from pathlib import Path

from aibom_inspector.parsers import SAFE_MAX_BYTES
from aibom_inspector.risk_engine import ScanConfig, run_scan


def _base_config(tmp_path: Path, *, fail_on_score: int | None = None, baseline_report: str | None = None) -> ScanConfig:
    req_path = tmp_path / "requirements.txt"
    req_path.write_text("requests==2.32.0\n")

    return ScanConfig(
        requirements_path=str(req_path),
        pyproject_path=None,
        models_file=None,
        model_id=(),
        manifest=(),
        sbom_file=(),
        with_cves=False,
        risk_max_score=100,
        risk_penalty_high=None,
        risk_penalty_medium=None,
        risk_penalty_low=None,
        risk_penalty_governance=None,
        risk_penalty_cve=None,
        fail_on_score=fail_on_score,
        include_shadow_repo=False,
        shadow_timeout=None,
        shadow_repo_url=None,
        offline=True,
        osv_url=None,
        osv_timeout=None,
        model_advisory_db=None,
        model_hash_db=None,
        threat_taxonomy_db=None,
        license_risk_db=None,
        training_source_db=None,
        require_input=False,
        approval=(),
        registry_allowlist=(),
        protected_namespace=(),
        require_dependency_signatures=False,
        lockfile_checksum=(),
        enforce_lockfile_checksums_flag=False,
        config_checksum=(),
        ruleset_checksum=(),
        plugin_signature=(),
        discover_stack_flag=False,
        env="dev",
        policy=None,
        enforce_graph_policy=True,
        runtime_trace=None,
        baseline_report=baseline_report,
        ai_summary=False,
        max_manifest_bytes=SAFE_MAX_BYTES,
    )


def test_fail_on_score_flags_result(tmp_path: Path) -> None:
    config = _base_config(tmp_path, fail_on_score=101)

    result = run_scan(config)

    assert result.score_failed is True


def test_baseline_diff_generation(tmp_path: Path) -> None:
    initial = run_scan(_base_config(tmp_path))
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(initial.report_json))

    config = _base_config(tmp_path, baseline_report=str(baseline_path))
    result = run_scan(config)

    assert result.baseline_diff is not None
    assert "stack_risk_delta" in result.baseline_diff
