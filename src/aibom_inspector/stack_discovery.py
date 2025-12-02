from __future__ import annotations

import json
import re
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

try:  # Optional dependency; discovery should still run without YAML
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    yaml = None

from .policy_graph import GraphEdge, GraphNode, GraphSnapshot
from .types import (
    DependencyInfo,
    ModelInfo,
    ModelIssue,
    apply_license_category_model,
)


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

MODEL_HOST_DEPENDENCIES = {
    "transformers": "huggingface",
    "torch": "pytorch",
    "tensorflow": "tensorflow",
    "tf-nightly": "tensorflow",
    "torchvision": "pytorch",
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
    "langsmith": "langchain",
    **MODEL_HOST_DEPENDENCIES,
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
    "OPENAI_MODEL",
    "ANTHROPIC_MODEL",
    "MODEL_ID",
    "HF_HOME",
    "TRANSFORMERS_CACHE",
}

MODEL_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(gpt-[\w-]+)\b", re.IGNORECASE), "openai"),
    (re.compile(r"\bclaude[-\w]*\b", re.IGNORECASE), "anthropic"),
    (re.compile(r"\b(?:meta-)?llama[-/\w]*\b", re.IGNORECASE), "meta"),
]

MODEL_LOAD_PATTERNS: List[Tuple[re.Pattern[str], str | None]] = [
    (re.compile(r"from_pretrained\(\s*[\"']([\w./:-]+)[\"']", re.IGNORECASE), "huggingface"),
    (re.compile(r"pipeline\([^\)]*model\s*=\s*[\"']([\w./:-]+)[\"']", re.IGNORECASE), "huggingface"),
    (re.compile(r"model_id\s*=\s*[\"']([\w./:-]+)[\"']"), None),
    (re.compile(r"\"model\"\s*:\s*\"([^\"]+)\""), None),
    (re.compile(r"model_name\s*=\s*[\"']([\w./:-]+)[\"']"), None),
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


def _infer_source(identifier: str, dependency_hint: str | None = None, explicit: str | None = None) -> str:
    if explicit:
        return explicit
    lowered = identifier.lower()
    if lowered.startswith("gpt") or lowered.startswith("o1"):
        return "openai"
    if lowered.startswith("claude"):
        return "anthropic"
    if "llama" in lowered:
        return "meta"
    if "/" in identifier or lowered.startswith("hf://"):
        return "huggingface"
    if dependency_hint:
        return dependency_hint
    return "inferred"


def discover_models(
    root: Path | str = Path("."), *, dependencies: Iterable[DependencyInfo] | None = None
) -> list[ModelInfo]:
    """Best-effort model autodiscovery from source/config files and dependency hints."""

    root_path = Path(root)
    discovered: dict[str, ModelInfo] = {}

    provider_hints = {
        dep.name.lower(): PROVIDER_DEPENDENCIES.get(dep.name.lower())
        for dep in dependencies or []
        if PROVIDER_DEPENDENCIES.get(dep.name.lower())
    }
    dependency_source_hint = next(iter(provider_hints.values())) if provider_hints else None

    def _record(identifier: str, *, explicit_source: str | None, evidence: str) -> None:
        if not identifier:
            return
        normalized = identifier.strip()
        source = _infer_source(normalized, dependency_source_hint, explicit_source)
        version_hint = _model_version_hint(normalized)

        model = discovered.get(normalized)
        if not model:
            model = ModelInfo(
                identifier=normalized,
                source=source,
                issues=[
                    ModelIssue(
                        "[UNKNOWN_LICENSE] Missing license information",
                        severity="high",
                        code="UNKNOWN_LICENSE",
                    )
                ],
            )
            apply_license_category_model(model)
            model.trust_signals.append(
                ModelIssue(
                    "[INFERRED_MODEL] Model reference auto-discovered from project files",
                    severity="low",
                    code="INFERRED_MODEL",
                )
            )
            discovered[normalized] = model

        model.source = model.source or source
        if version_hint and not model.last_updated:
            try:
                model.last_updated = datetime.fromisoformat(version_hint)
            except Exception:
                pass
        metadata_source = model.trust_signals[0].message if model.trust_signals else ""
        if evidence not in metadata_source:
            model.trust_signals.append(
                ModelIssue(
                    f"[EVIDENCE] discovered in {evidence}", severity="low", code="EVIDENCE"
                )
            )

    for path in root_path.rglob("*"):
        if path.is_dir():
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS and path.name not in {".env", ".env.example"}:
            continue
        text = _safe_read(path)
        if not text:
            continue

        for pattern, provider in MODEL_PATTERNS:
            for match in pattern.findall(text):
                identifier = match if isinstance(match, str) else match[0]
                _record(identifier, explicit_source=provider, evidence=str(path))

        for pattern, provider in MODEL_LOAD_PATTERNS:
            for match in pattern.findall(text):
                identifier = match if isinstance(match, str) else match[0]
                _record(identifier, explicit_source=provider, evidence=str(path))

    for dep in dependencies or []:
        if dep.name.lower() in MODEL_HOST_DEPENDENCIES:
            _record(dep.name, explicit_source=MODEL_HOST_DEPENDENCIES[dep.name.lower()], evidence=dep.source)

    return list(discovered.values())


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

    provider_hint = None
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
            provider_hint = provider
            _add_node(
                nodes,
                GraphNode(
                    id=provider,
                    kind="Provider",
                    metadata={"evidence": f"dependency:{dep.source}", "sdk": dep.name},
                ),
            )
        if normalized in MODEL_HOST_DEPENDENCIES:
            _add_node(
                nodes,
                GraphNode(
                    id=dep.name,
                    kind="ModelHost",
                    metadata={"evidence": f"dependency:{dep.source}", "provider": MODEL_HOST_DEPENDENCIES[normalized]},
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

        for pattern, provider in MODEL_LOAD_PATTERNS:
            for match in pattern.findall(text):
                identifier = match if isinstance(match, str) else match[0]
                inferred_source = _infer_source(identifier, provider_hint, provider)
                _add_node(
                    nodes,
                    GraphNode(
                        id=identifier,
                        kind="Model",
                        metadata={"provider": inferred_source, "evidence": str(path)},
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
