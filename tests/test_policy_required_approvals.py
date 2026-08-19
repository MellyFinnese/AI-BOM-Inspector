from datetime import datetime

from aibom_inspector.policy import Policy, evaluate_policy
from aibom_inspector.types import Report


def _report(approvals: list[str]) -> Report:
    return Report(dependencies=[], models=[], generated_at=datetime.utcnow(), approvals=approvals)


def test_all_required_approvals_must_be_present():
    policy = Policy(required_approvals=["security", "legal"])

    # Only one of two required approvals present: must fail.
    evaluation = evaluate_policy(_report(["security"]), policy)
    assert not evaluation.passed
    assert any("approval" in f.lower() for f in evaluation.failures)


def test_all_required_approvals_present_passes():
    policy = Policy(required_approvals=["security", "legal"])

    evaluation = evaluate_policy(_report(["security", "legal"]), policy)
    assert evaluation.passed


def test_required_approvals_case_insensitive_and_order_independent():
    policy = Policy(required_approvals=["Security", "Legal"])

    evaluation = evaluate_policy(_report(["legal", "SECURITY", "extra-approval"]), policy)
    assert evaluation.passed


def test_no_approvals_present_fails():
    policy = Policy(required_approvals=["security", "legal"])

    evaluation = evaluate_policy(_report([]), policy)
    assert not evaluation.passed
