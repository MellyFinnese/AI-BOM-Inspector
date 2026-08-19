from datetime import datetime

from aibom_inspector.policy import Policy, evaluate_policy
from aibom_inspector.types import DependencyInfo, Report


def test_publisher_expectation_with_none_source_does_not_crash():
    # dep.source is None (malformed/absent source data). Policy evaluation must
    # not raise, and should produce a controlled (failing) policy result rather
    # than silently passing or throwing a TypeError.
    dep = DependencyInfo(name="left-pad", version="1.0.0", source=None)
    report = Report(dependencies=[dep], models=[], generated_at=datetime.utcnow())
    policy = Policy(publisher_expectations={"left-pad": "npm-official"})

    evaluation = evaluate_policy(report, policy)

    assert not evaluation.passed
    assert any("left-pad" in f for f in evaluation.failures)


def test_publisher_expectation_with_matching_source_passes():
    dep = DependencyInfo(name="left-pad", version="1.0.0", source="npm-official")
    report = Report(dependencies=[dep], models=[], generated_at=datetime.utcnow())
    policy = Policy(publisher_expectations={"left-pad": "npm-official"})

    evaluation = evaluate_policy(report, policy)

    assert evaluation.passed


def test_publisher_expectation_with_empty_source_fails_controlled():
    dep = DependencyInfo(name="left-pad", version="1.0.0", source="")
    report = Report(dependencies=[dep], models=[], generated_at=datetime.utcnow())
    policy = Policy(publisher_expectations={"left-pad": "npm-official"})

    evaluation = evaluate_policy(report, policy)

    assert not evaluation.passed
