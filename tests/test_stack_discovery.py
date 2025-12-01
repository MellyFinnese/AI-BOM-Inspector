from pathlib import Path

from aibom_inspector.stack_discovery import discover_stack
from aibom_inspector.types import DependencyInfo


def test_discover_stack_surfaces_agents_models_and_env(tmp_path: Path) -> None:
    (tmp_path / "mcp.json").write_text('{"permissions": ["read", "write"]}')
    (tmp_path / "app.py").write_text("model_id = 'gpt-4o'\nkey_name = 'OPENAI_API_KEY'\n")

    deps = [DependencyInfo(name="langgraph", version="0.1", source="requirements.txt", issues=[])]

    snapshot = discover_stack(tmp_path, dependencies=deps, models=[], env="prod")

    kinds = {(node.kind, node.id) for node in snapshot.nodes}
    assert ("Framework", "langgraph") in kinds
    assert any(node.kind == "Model" and "gpt-4o" in node.id for node in snapshot.nodes)
    assert any(node.kind == "EnvVar" and node.id == "OPENAI_API_KEY" for node in snapshot.nodes)

    mcp_nodes = [node for node in snapshot.nodes if node.kind == "MCPServer"]
    assert mcp_nodes and "write" in mcp_nodes[0].metadata.get("permissions", [])
    assert snapshot.context.get("env") == "prod"
