from datetime import datetime

from aibom_inspector.policy import Policy, evaluate_policy
from aibom_inspector.policy_graph import GraphNode, GraphSnapshot
from aibom_inspector.types import Report


def test_graph_policy_enforced_when_requested() -> None:
    snapshot = GraphSnapshot(
        nodes=[GraphNode(id="gpt-4o", kind="Model", metadata={})],
        context={"env": "prod"},
    )
    policy = Policy(enforce_graph_policies=True)

    report = Report(dependencies=[], models=[], generated_at=datetime.utcnow(), stack_snapshot=snapshot)

    evaluation = evaluate_policy(report, policy, graph_snapshot=snapshot, enforce_graph=True)

    assert not evaluation.passed
    assert any("model-unpinned-gpt-4o" in failure for failure in evaluation.failures)
    assert evaluation.graph_policy_violations
