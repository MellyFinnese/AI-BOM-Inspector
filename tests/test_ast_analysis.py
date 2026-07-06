from pathlib import Path

from aibom_inspector.ast_analysis import analyze_javascript_source, analyze_python_source
from aibom_inspector.stack_discovery import discover_models, discover_stack


def test_python_ast_resolves_model_alias_kwargs(tmp_path: Path) -> None:
    code = """
from openai import OpenAI as Client

MODEL_NAME = "gpt-4o-mini"
client = Client()
client.chat.completions.create(model=MODEL_NAME, messages=[])
"""
    path = tmp_path / "app.py"
    path.write_text(code)

    evidence = analyze_python_source(path, code)

    assert any(item.identifier == "gpt-4o-mini" and item.provider == "openai" for item in evidence)


def test_javascript_structural_scan_resolves_model_binding(tmp_path: Path) -> None:
    code = """
import OpenAI from "openai";
const selectedModel = "gpt-4.1-mini";
await client.chat.completions.create({
  model: selectedModel,
  messages: []
});
"""
    path = tmp_path / "app.js"
    path.write_text(code)

    evidence = analyze_javascript_source(path, code)

    assert any(item.identifier == "gpt-4.1-mini" and item.provider == "openai" for item in evidence)


def test_discovery_uses_ast_evidence_for_static_models(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """
from anthropic import Anthropic
MODEL = "claude-3-5-sonnet-latest"
Anthropic().messages.create(model=MODEL, messages=[])
"""
    )

    models = discover_models(tmp_path)
    snapshot = discover_stack(tmp_path)

    assert any(model.identifier == "claude-3-5-sonnet-latest" for model in models)
    assert any(
        node.kind == "Model"
        and node.id == "claude-3-5-sonnet-latest"
        and node.metadata.get("analysis") == "ast"
        for node in snapshot.nodes
    )
