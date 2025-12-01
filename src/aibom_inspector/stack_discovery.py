from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

try:  # Optional dependency; discovery should still run without YAML
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    yaml = None

from .policy_graph import GraphEdge, GraphNode, GraphSnapshot
from .types import DependencyInfo, ModelInfo


TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".md",
    ".txt",
}

AGENT_DEPENDENCIES = {
    "langchain",
    "langgraph",
    "llama-index",
    "semantic-kernel",
    "autogen",
    "haystack",
    "crewai",
}

PROVIDER_DEPENDENCIES = {
    "openai": "openai",
    "anthropic": "anthropic",
    "google-generativeai": "google",
    "vertexai": "google",
    "boto3": "aws",
    "bedrock": "aws",
    "azure-ai-ml": "azure",
    "azure-core": "azure",
}

ENV_VAR_CLUES = {
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_API_KEY",
    "GOOGLE_API_KEY",
    "VERTEXAI_PROJECT",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "MCP_CONFIG",
}

MODEL_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(gpt-[\w-]+)\b", re.IGNORECASE), "openai"),
    (re.compile(r"\bclaude[-\w]*\b", re.IGNORECASE), "anthropic"),
    (re.compile(r"\b(?:meta-)?llama[-/\w]*\b", re.IGNORECASE), "meta"),
]

TOOL_CAPABILITY_PATTERNS: Dict[str, re.Pattern[str]] = {
    "exec.shell": re.compile(r"exec\.shell|subprocess\.run|os\.system", re.IGNORECASE),
    "fs.write": re.compile(r"fs\.write|open\([^)]*['\"]w['\"]", re.IGNORECASE),
}


def _safe_read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        try:
            return path.read_text(errors="ignore")
        except Exception:
            return ""


def _add_node(nodes: Dict[Tuple[str, str], GraphNode], node: GraphNode) -> None:
    key = (node.kind, node.id)
    if key not in nodes:
        nodes[key] = node
        return
    existing = nodes[key]
    merged = {**existing.metadata}
    merged.update(node.metadata)
    existing.metadata = merged


def _maybe_parse_permissions(path: Path) -> List[str]:
    content = _safe_read(path)
    try:
        data = json.loads(content)
    except Exception:
        if yaml is None:
            return []
        try:
            data = yaml.safe_load(content)
        except Exception:
            return []

    if not isinstance(data, dict):
        return []
    permissions = data.get("permissions") or data.get("scopes")
    if isinstance(permissions, list):
        return [str(p) for p in permissions if isinstance(p, (str, int, float))]
    return []


def _model_version_hint(identifier: str) -> str:
    if any(sep in identifier for sep in {":", "@"}):
        return identifier.split(":", 1)[-1].split("@", 1)[-1]
    if re.search(r"\d{4}[-/]?\d{2}", identifier):
        return identifier
    return ""


def discover_stack(
    root: Path | str = Path("."),
    *,
    dependencies: Iterable[DependencyInfo] | None = None,
    models: Iterable[ModelInfo] | None = None,
    env: str | None = None,
) -> GraphSnapshot:
    """Detect AI stack components (agents, tools, providers, configs) from a project tree."""

    root_path = Path(root)
    nodes: Dict[Tuple[str, str], GraphNode] = {}
    edges: list[GraphEdge] = []

    for dep in dependencies or []:
        normalized = dep.name.lower()
        if normalized in AGENT_DEPENDENCIES:
            _add_node(
                nodes,
                GraphNode(
                    id=dep.name,
                    kind="Framework",
                    metadata={"evidence": f"dependency:{dep.source}", "category": "agent"},
                ),
            )
        provider = PROVIDER_DEPENDENCIES.get(normalized)
        if provider:
            _add_node(
                nodes,
                GraphNode(
                    id=provider,
                    kind="Provider",
                    metadata={"evidence": f"dependency:{dep.source}", "sdk": dep.name},
                ),
            )

    for model in models or []:
        version_hint = _model_version_hint(model.identifier)
        _add_node(
            nodes,
            GraphNode(
                id=model.identifier,
                kind="Model",
                metadata={
                    "version": version_hint,
                    "source": model.source,
                    "evidence": "model-list",
                },
            ),
        )

    for path in root_path.rglob("*"):
        if path.is_dir():
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS and path.name not in {".env", ".env.example"}:
            continue
        text = _safe_read(path)
        if not text:
            continue

        for env_var in ENV_VAR_CLUES:
            if env_var in text:
                _add_node(
                    nodes,
                    GraphNode(
                        id=env_var,
                        kind="EnvVar",
                        metadata={"evidence": str(path)},
                    ),
                )

        for pattern, provider in MODEL_PATTERNS:
            for match in pattern.findall(text):
                identifier = match if isinstance(match, str) else match[0]
                _add_node(
                    nodes,
                    GraphNode(
                        id=identifier,
                        kind="Model",
                        metadata={"provider": provider, "evidence": str(path)},
                    ),
                )

        if "mcp" in path.name.lower():
            permissions = _maybe_parse_permissions(path)
            _add_node(
                nodes,
                GraphNode(
                    id=path.stem,
                    kind="MCPServer",
                    metadata={"permissions": permissions, "evidence": str(path)},
                ),
            )

        capabilities: Dict[str, bool] = {}
        for capability, pattern in TOOL_CAPABILITY_PATTERNS.items():
            if pattern.search(text):
                capabilities[capability] = True
        if capabilities:
            _add_node(
                nodes,
                GraphNode(
                    id=path.stem,
                    kind="Tool",
                    metadata={"capabilities": capabilities, "evidence": str(path)},
                ),
            )

    snapshot = GraphSnapshot(nodes=list(nodes.values()), edges=edges, context={})
    if env:
        snapshot.context["env"] = env
    return snapshot


def snapshot_as_dict(snapshot: GraphSnapshot) -> dict:
    return {
        "nodes": [asdict(node) for node in snapshot.nodes],
        "edges": [asdict(edge) for edge in snapshot.edges],
        "context": dict(snapshot.context),
    }
