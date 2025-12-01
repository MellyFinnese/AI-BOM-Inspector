from aibom_inspector.policy_graph import (
    GraphEdge,
    GraphNode,
    GraphSnapshot,
    evaluate_graph_policies,
)


def test_mcp_write_blocked_in_prod():
    snapshot = GraphSnapshot(
        nodes=[
            GraphNode(
                id="notion-mcp",
                kind="MCPServer",
                metadata={"permissions": ["read", "write"], "evidence": "mcp.json:12"},
            )
        ],
        context={"env": "prod"},
    )

    violations = evaluate_graph_policies(snapshot)

    assert any(v.id == "mcp-write-notion-mcp" for v in violations)


def test_tool_with_broad_fs_access_is_denied():
    snapshot = GraphSnapshot(
        nodes=[
            GraphNode(
                id="fs-wildcard",
                kind="Tool",
                metadata={
                    "capabilities": {"fs.write": True},
                    "allowed_paths": ["**/*"],
                },
            )
        ]
    )

    violations = evaluate_graph_policies(snapshot)

    assert any(v.id == "tool-fs-broad-fs-wildcard" for v in violations)


def test_shell_tool_accessible_to_agent_in_prod_is_denied():
    snapshot = GraphSnapshot(
        nodes=[
            GraphNode(
                id="shell-tool",
                kind="Tool",
                metadata={"capabilities": {"exec.shell": True}},
            )
        ],
        edges=[GraphEdge(source="shell-tool", target="chat-agent", kind="agent_uses_tool")],
        context={"env": "prod"},
    )

    violations = evaluate_graph_policies(snapshot)

    assert any(v.id == "tool-shell-prod-shell-tool" for v in violations)


def test_unpinned_models_in_prod_fail():
    snapshot = GraphSnapshot(
        nodes=[
            GraphNode(id="gpt-4o", kind="Model", metadata={}),
            GraphNode(id="claude-sonnet", kind="Model", metadata={"version": "202406"}),
        ],
        context={"env": "prod"},
    )

    violations = evaluate_graph_policies(snapshot)

    assert any(v.id == "model-unpinned-gpt-4o" for v in violations)
    assert all(v.id != "model-unpinned-claude-sonnet" for v in violations)
