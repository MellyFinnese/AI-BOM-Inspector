from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional

try:  # Optional dependency so we can still run without policy files
    import yaml
except Exception:  # pragma: no cover - exercised when PyYAML is missing
    yaml = None

from .types import DependencyIssue, ModelIssue, Report


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
    exceptions: List[PolicyException] = field(default_factory=list)


@dataclass
class PolicyEvaluation:
    passed: bool
    failures: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    used_exceptions: List[PolicyException] = field(default_factory=list)
    expired_exceptions: List[PolicyException] = field(default_factory=list)

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
        }


def _load_yaml(path: Path) -> dict:
    if yaml is None:
        raise RuntimeError("PyYAML is required to load policy files. Install with `pip install pyyaml`.")
    return yaml.safe_load(path.read_text()) or {}


def load_policy(path: Path) -> Policy:
    raw = _load_yaml(path)
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
        exceptions=exceptions,
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


def evaluate_policy(report: Report, policy: Policy) -> PolicyEvaluation:
    failures: list[str] = []
    warnings: list[str] = []
    used_exceptions: list[PolicyException] = []
    expired: list[PolicyException] = []
    now = datetime.utcnow()

    if policy.min_score is not None and report.stack_risk_score < policy.min_score:
        failures.append(
            f"Stack risk score {report.stack_risk_score} below policy minimum {policy.min_score}"
        )

    if policy.max_cves is not None:
        cve_hits = report.risk_breakdown.get("cves", 0)
        if cve_hits > policy.max_cves:
            failures.append(f"Detected {cve_hits} CVE/advisory hits (max allowed {policy.max_cves})")

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

    for exc in policy.exceptions:
        if exc.expires and exc.expires < now:
            expired.append(exc)
            warnings.append(
                f"Exception for {exc.subject} ({exc.code}) expired on {exc.expires.isoformat()}"
            )

    return PolicyEvaluation(
        passed=not failures,
        failures=failures,
        warnings=warnings,
        used_exceptions=used_exceptions,
        expired_exceptions=expired,
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
) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    (destination / report_filename.name).write_text(report_content)
    if evaluation:
        (destination / "policy-evaluation.json").write_text(
            json.dumps(evaluation.as_dict(), indent=2)
        )
    if policy_path and policy_path.exists():
        policy_dest = destination / policy_path.name
        if policy_dest.resolve() != policy_path.resolve():
            policy_dest.write_text(policy_path.read_text())
    if diff_summary:
        (destination / "changes-since-last-run.json").write_text(
            json.dumps(diff_summary, indent=2)
        )
    if signature_text:
        (destination / f"{report_filename.name}.sha256").write_text(signature_text)
