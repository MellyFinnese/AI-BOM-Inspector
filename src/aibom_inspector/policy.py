from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional

from pydantic import ValidationError

from .policy_graph import GraphPolicyViolation, GraphSnapshot, evaluate_graph_policies
from .types import DependencyIssue, ModelIssue, Report
from .trust_root import TrustRoot, sign_payload, trust_root_fingerprint
from .parsers import ParserError, parse_policy_file, serialize_validation_errors


@dataclass
class PolicyException:
    code: str
    subject: str
    reason: str = ""
    approved_by: Optional[str] = None
    expires: Optional[datetime] = None


@dataclass
class Policy:
    min_score: Optional[int] = None
    max_cves: Optional[int] = None
    disallow: List[str] = field(default_factory=list)
    min_trust_score: Optional[int] = None
    publisher_expectations: dict[str, str] = field(default_factory=dict)
    trusted_registries: List[str] = field(default_factory=list)
    protected_namespaces: List[str] = field(default_factory=list)
    require_dependency_signatures: bool = False
    required_approvals: List[str] = field(default_factory=list)
    lockfile_checksums: dict[str, str] = field(default_factory=dict)
    require_lockfile_checksums: bool = False
    config_checksums: dict[str, str] = field(default_factory=dict)
    ruleset_checksums: dict[str, str] = field(default_factory=dict)
    plugin_signatures: dict[str, str] = field(default_factory=dict)
    exceptions: List[PolicyException] = field(default_factory=list)
    enforce_graph_policies: bool = False
    scoring_model: str | None = None
    scoring_model_version: str | None = None
    category_weights: dict[str, float] = field(default_factory=dict)
    weight_scale: float | None = None
    org_weights: dict[str, int] = field(default_factory=dict)
    temporal_multipliers: dict[str, float] = field(default_factory=dict)
    asset_criticality_multipliers: dict[str, float] = field(default_factory=dict)
    data_sensitivity_multipliers: dict[str, float] = field(default_factory=dict)
    environment_multipliers: dict[str, float] = field(default_factory=dict)
    missing_intel_penalty: int | None = None
    active_exploitation_penalty: int | None = None
    policy_version: str | None = None
    change_log: list[dict] = field(default_factory=list)


@dataclass
class PolicyEvaluation:
    passed: bool
    failures: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    used_exceptions: List[PolicyException] = field(default_factory=list)
    expired_exceptions: List[PolicyException] = field(default_factory=list)
    graph_policy_violations: List[GraphPolicyViolation] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "passed": self.passed,
            "failures": self.failures,
            "warnings": self.warnings,
            "used_exceptions": [
                {
                    "code": exc.code,
                    "subject": exc.subject,
                    "reason": exc.reason,
                    "approved_by": exc.approved_by,
                    "expires": exc.expires.isoformat() if exc.expires else None,
                }
                for exc in self.used_exceptions
            ],
            "expired_exceptions": [
                {
                    "code": exc.code,
                    "subject": exc.subject,
                    "reason": exc.reason,
                    "approved_by": exc.approved_by,
                    "expires": exc.expires.isoformat() if exc.expires else None,
                }
                for exc in self.expired_exceptions
            ],
            "graph_violations": [
                {
                    "id": violation.id,
                    "severity": violation.severity,
                    "message": violation.message,
                    "evidence": violation.evidence,
                    "suggested_fixes": violation.suggested_fixes,
                }
                for violation in self.graph_policy_violations
            ],
        }


def load_policy(path: Path, *, max_bytes: int | None = None) -> Policy:
    try:
        raw_payload = parse_policy_file(path, max_bytes=max_bytes)
    except ParserError as exc:
        raise RuntimeError(str(exc)) from exc
    except ValidationError as exc:
        details = serialize_validation_errors(exc.errors())
        detail_text = "; ".join(details) if details else "invalid policy schema"
        raise RuntimeError(f"Invalid policy schema: {detail_text}") from exc

    raw = raw_payload.model_dump()
    exceptions: list[PolicyException] = []
    for entry in raw.get("exceptions", []) or []:
        expires_at = entry.get("expires") if isinstance(entry, dict) else None
        parsed_expires = None
        if expires_at:
            try:
                parsed_expires = datetime.fromisoformat(str(expires_at))
            except Exception:
                parsed_expires = None
        exceptions.append(
            PolicyException(
                code=str(entry.get("code")),
                subject=str(entry.get("subject")),
                reason=str(entry.get("reason", "")),
                approved_by=entry.get("approved_by"),
                expires=parsed_expires,
            )
        )

    return Policy(
        min_score=raw.get("min_score"),
        max_cves=raw.get("max_cves"),
        disallow=raw.get("disallow") or raw.get("blocklist") or [],
        min_trust_score=raw.get("min_trust_score"),
        publisher_expectations=raw.get("publisher_expectations") or {},
        trusted_registries=raw.get("trusted_registries") or [],
        protected_namespaces=raw.get("protected_namespaces") or [],
        require_dependency_signatures=bool(raw.get("require_dependency_signatures", False)),
        required_approvals=raw.get("required_approvals") or [],
        lockfile_checksums=raw.get("lockfile_checksums") or {},
        require_lockfile_checksums=bool(raw.get("require_lockfile_checksums", False)),
        config_checksums=raw.get("config_checksums") or {},
        ruleset_checksums=raw.get("ruleset_checksums") or {},
        plugin_signatures=raw.get("plugin_signatures") or {},
        exceptions=exceptions,
        enforce_graph_policies=bool(raw.get("enforce_graph_policies", False)),
        scoring_model=raw.get("scoring_model"),
        scoring_model_version=raw.get("scoring_model_version"),
        category_weights=raw.get("category_weights") or {},
        weight_scale=raw.get("weight_scale"),
        org_weights=raw.get("org_weights") or {},
        temporal_multipliers=raw.get("temporal_multipliers") or {},
        asset_criticality_multipliers=raw.get("asset_criticality_multipliers") or {},
        data_sensitivity_multipliers=raw.get("data_sensitivity_multipliers") or {},
        environment_multipliers=raw.get("environment_multipliers") or {},
        missing_intel_penalty=raw.get("missing_intel_penalty"),
        active_exploitation_penalty=raw.get("active_exploitation_penalty"),
        policy_version=raw.get("policy_version") or raw.get("version"),
        change_log=raw.get("change_log") or [],
    )


def _issue_code(issue: DependencyIssue | ModelIssue) -> str:
    return str(issue.code or issue.message)


def _match_exception(
    issue: DependencyIssue | ModelIssue, subject: str, policy: Policy, now: datetime
) -> PolicyException | None:
    for exc in policy.exceptions:
        if exc.code != _issue_code(issue) or exc.subject != subject:
            continue
        if exc.expires and exc.expires < now:
            continue
        return exc
    return None


def evaluate_policy(
    report: Report,
    policy: Policy,
    graph_snapshot: GraphSnapshot | None = None,
    enforce_graph: bool = False,
) -> PolicyEvaluation:
    failures: list[str] = []
    warnings: list[str] = []
    used_exceptions: list[PolicyException] = []
    expired: list[PolicyException] = []
    now = datetime.utcnow()

    if policy.min_score is not None and report.stack_risk_score < policy.min_score:
        failures.append(f"Stack risk score {report.stack_risk_score} below policy minimum {policy.min_score}")

    if policy.max_cves is not None:
        cve_hits = report.risk_breakdown.get("cves", 0)
        if cve_hits > policy.max_cves:
            failures.append(f"Detected {cve_hits} CVE/advisory hits (max allowed {policy.max_cves})")

    if policy.required_approvals:
        approvals = {approval.lower() for approval in report.approvals}
        required = {approval.lower() for approval in policy.required_approvals}
        if not approvals.intersection(required):
            failures.append(
                f"Missing required approvals: {', '.join(sorted(policy.required_approvals))}"
            )

    def _check_subject(
        subject: str, issues: Iterable[DependencyIssue | ModelIssue], trust_score: int
    ) -> None:
        for issue in issues:
            if policy.disallow and _issue_code(issue) in policy.disallow:
                matched = _match_exception(issue, subject, policy, now)
                if matched:
                    used_exceptions.append(matched)
                    continue
                failures.append(f"{subject}: {_issue_code(issue)} blocked by policy")

        if policy.min_trust_score is not None and trust_score < policy.min_trust_score:
            failures.append(
                f"{subject}: trust score {trust_score} below policy floor {policy.min_trust_score}"
            )

    for dep in report.dependencies:
        _check_subject(dep.name, dep.issues + dep.trust_signals, dep.trust_score)
        expected_publisher = policy.publisher_expectations.get(dep.name)
        if expected_publisher and expected_publisher not in dep.source:
            failures.append(
                f"{dep.name}: publisher/source '{dep.source}' did not match expected '{expected_publisher}'"
            )

    for model in report.models:
        _check_subject(model.identifier, model.issues + model.trust_signals, model.trust_score)

    for finding in report.integrity_findings:
        entry = f"[integrity:{finding.code or finding.kind}] {finding.message}"
        if finding.severity.lower() == "high":
            failures.append(entry)
        else:
            warnings.append(entry)

    for exc in policy.exceptions:
        if exc.expires and exc.expires < now:
            expired.append(exc)
            warnings.append(f"Exception for {exc.subject} ({exc.code}) expired on {exc.expires.isoformat()}")

    graph_violations: list[GraphPolicyViolation] = []
    if graph_snapshot and enforce_graph:
        graph_violations = evaluate_graph_policies(graph_snapshot)
        for violation in graph_violations:
            entry = f"[graph:{violation.id}] {violation.message}"
            if violation.severity.lower() == "error":
                failures.append(entry)
            else:
                warnings.append(entry)

    return PolicyEvaluation(
        passed=not failures,
        failures=failures,
        warnings=warnings,
        used_exceptions=used_exceptions,
        expired_exceptions=expired,
        graph_policy_violations=graph_violations,
    )


def write_github_check(path: Path, evaluation: PolicyEvaluation, report: Report) -> None:
    payload = {
        "conclusion": "success" if evaluation.passed else "failure",
        "summary": "; ".join(evaluation.failures) if evaluation.failures else "All policy checks passed.",
        "details": evaluation.as_dict(),
        "stack_risk_score": report.stack_risk_score,
        "risk_breakdown": report.risk_breakdown,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


def diff_reports(base: dict, target: dict) -> dict:
    base_deps = {d["name"]: d for d in base.get("dependencies", [])}
    target_deps = {d["name"]: d for d in target.get("dependencies", [])}

    added = sorted(set(target_deps) - set(base_deps))
    removed = sorted(set(base_deps) - set(target_deps))

    changed = []
    for name in set(base_deps).intersection(target_deps):
        if base_deps[name].get("issues") != target_deps[name].get("issues"):
            changed.append(name)

    return {
        "added_dependencies": added,
        "removed_dependencies": removed,
        "changed_dependencies": sorted(changed),
        "stack_risk_delta": target.get("stack_risk_score", 0) - base.get("stack_risk_score", 0),
    }


def serialize_report(report: Report) -> dict:
    # Reuse the JSON renderer data without formatting
    return json.loads(json.dumps(asdict(report), default=str))


def write_evidence_pack(
    destination: Path,
    report_content: str,
    report_filename: Path,
    evaluation: Optional[PolicyEvaluation],
    policy_path: Path | None,
    diff_summary: dict | None,
    signature_text: str | None,
    evaluation_metadata: dict | None = None,
    previous_hash: str | None = None,
    trust_root: TrustRoot | None = None,
) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    (destination / report_filename.name).write_text(report_content)
    if evaluation:
        (destination / "policy-evaluation.json").write_text(json.dumps(evaluation.as_dict(), indent=2))
    if policy_path and policy_path.exists():
        policy_dest = destination / policy_path.name
        if policy_dest.resolve() != policy_path.resolve():
            policy_dest.write_text(policy_path.read_text())
    if diff_summary:
        (destination / "changes-since-last-run.json").write_text(json.dumps(diff_summary, indent=2))
    if evaluation_metadata:
        (destination / "evaluation-metadata.json").write_text(
            json.dumps(evaluation_metadata, indent=2)
        )
        score_explanation = evaluation_metadata.get("score_explanation")
        if score_explanation:
            (destination / "score-explanation.json").write_text(
                json.dumps(score_explanation, indent=2)
            )
    if signature_text:
        (destination / f"{report_filename.name}.sha256").write_text(signature_text)
    _write_evidence_manifest(destination, previous_hash=previous_hash)
    if trust_root:
        _write_evidence_signatures(destination, report_filename, trust_root)


def _hash_manifest(payload: dict, previous_hash: str | None) -> str:
    digest = hashlib.sha256()
    digest.update((previous_hash or "").encode())
    digest.update(json.dumps(payload, sort_keys=True).encode())
    return digest.hexdigest()


def _write_evidence_manifest(destination: Path, previous_hash: str | None = None) -> None:
    files: dict[str, str] = {}
    for path in sorted(destination.glob("*")):
        if not path.is_file():
            continue
        if path.name == "evidence-manifest.json":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        files[path.name] = digest

    payload = {
        "generated_at": datetime.utcnow().isoformat(),
        "files": files,
        "previous_hash": previous_hash,
    }
    payload["bundle_hash"] = _hash_manifest(payload, previous_hash)
    (destination / "evidence-manifest.json").write_text(json.dumps(payload, indent=2))


def _write_signature_file(destination: Path, name: str, payload: dict, trust_root: TrustRoot) -> None:
    signature = sign_payload(payload, trust_root)
    signature_payload = {
        "signed_at": datetime.utcnow().isoformat(),
        "key_id": trust_root.key_id,
        "algorithm": trust_root.algorithm,
        "fingerprint": trust_root_fingerprint(trust_root),
        "payload": payload,
        "signature": signature,
    }
    (destination / name).write_text(json.dumps(signature_payload, indent=2))


def _write_evidence_signatures(
    destination: Path, report_filename: Path, trust_root: TrustRoot
) -> None:
    manifest_path = destination / "evidence-manifest.json"
    if manifest_path.exists():
        manifest_payload = json.loads(manifest_path.read_text())
        manifest_payload["kind"] = "evidence-manifest"
        _write_signature_file(destination, "evidence-manifest.sig.json", manifest_payload, trust_root)

    report_path = destination / report_filename.name
    if report_path.exists():
        report_hash = hashlib.sha256(report_path.read_bytes()).hexdigest()
        report_payload = {
            "kind": "report",
            "filename": report_filename.name,
            "sha256": report_hash,
            "generated_at": datetime.utcnow().isoformat(),
        }
        _write_signature_file(
            destination,
            f"{report_filename.name}.sig.json",
            report_payload,
            trust_root,
        )
