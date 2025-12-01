"""Graph policy evaluation helpers.

This module provides a small, hard-coded ruleset that mirrors the practical
examples outlined in the policy documentation. It is intentionally lightweight
so callers can supply a simple graph snapshot (nodes + edges + context) and get
structured violations back without pulling in an external policy engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, List, Optional


@dataclass
class GraphNode:
    """A normalized representation of a discovered stack component."""

    id: str
    kind: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """A normalized relationship between two nodes."""

    source: str
    target: str
    kind: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphSnapshot:
    """Container for graph facts and optional evaluation context."""

    nodes: List[GraphNode]
    edges: List[GraphEdge] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    def find_nodes(self, kind: str) -> Iterable[GraphNode]:
        for node in self.nodes:
            if node.kind.lower() == kind.lower():
                yield node

    def edges_from(self, source_id: str, kind: Optional[str] = None) -> Iterable[GraphEdge]:
        for edge in self.edges:
            if edge.source != source_id:
                continue
            if kind and edge.kind.lower() != kind.lower():
                continue
            yield edge


@dataclass
class GraphPolicyViolation:
    """A policy violation emitted by graph evaluation."""

    id: str
    severity: str
    message: str
    evidence: List[str] = field(default_factory=list)
    suggested_fixes: List[str] = field(default_factory=list)


def evaluate_graph_policies(snapshot: GraphSnapshot) -> List[GraphPolicyViolation]:
    """Evaluate high-signal default policies against a graph snapshot.

    The evaluation mirrors the examples in the policy guide:
    - No MCP server with write scope in prod.
    - No tool combining tool-calling with broad filesystem write.
    - No agent using a shell/exec-capable tool in prod.
    - Models must be pinned in prod.
    """

    env = str(snapshot.context.get("env", "dev")).lower()
    violations: list[GraphPolicyViolation] = []

    # No MCP server with write scope in prod
    if env == "prod":
        for mcp in snapshot.find_nodes("MCPServer"):
            permissions = {p.lower() for p in mcp.metadata.get("permissions", []) if isinstance(p, str)}
            if "write" in permissions:
                evidence = []
                evidence_key = mcp.metadata.get("evidence")
                if evidence_key:
                    evidence.append(str(evidence_key))
                violations.append(
                    GraphPolicyViolation(
                        id=f"mcp-write-{mcp.id}",
                        severity="error",
                        message=f"MCP server {mcp.id} has write permissions in prod.",
                        evidence=evidence,
                        suggested_fixes=[
                            "Use a read-only variant for production.",
                            "Apply per-environment config overrides to narrow scopes.",
                            "Require human approval for write-scoped MCP servers.",
                        ],
                    )
                )

    # No tool calling + broad filesystem access
    for tool in snapshot.find_nodes("Tool"):
        capabilities = tool.metadata.get("capabilities", {}) or {}
        fs_write = bool(capabilities.get("fs.write") or capabilities.get("fs_write"))
        allowed_paths = tool.metadata.get("allowed_paths") or []
        broad_paths = {"/", "~", "**/*"}
        if fs_write and any(path in broad_paths for path in allowed_paths):
            evidence = []
            if allowed_paths:
                evidence.append(f"allowed_paths={allowed_paths}")
            violations.append(
                GraphPolicyViolation(
                    id=f"tool-fs-broad-{tool.id}",
                    severity="error",
                    message=f"Tool {tool.id} allows filesystem writes to broad paths.",
                    evidence=evidence,
                    suggested_fixes=[
                        "Constrain the tool to a sandbox directory (e.g., /var/app/workdir).",
                        "Replace broad globs with an explicit allowlist.",
                        "Require human approval for writes outside a narrow scope.",
                    ],
                )
            )

        # Deny agents calling shell tools in prod
        exec_shell = bool(capabilities.get("exec.shell") or capabilities.get("exec_shell"))
        if env == "prod" and exec_shell:
            agent_edges = list(snapshot.edges_from(tool.id, kind="agent_uses_tool"))
            if agent_edges:
                evidence = [f"edge {edge.source}->{edge.target}" for edge in agent_edges]
                violations.append(
                    GraphPolicyViolation(
                        id=f"tool-shell-prod-{tool.id}",
                        severity="error",
                        message=f"Shell/exec-capable tool {tool.id} is accessible to agents in prod.",
                        evidence=evidence,
                        suggested_fixes=[
                            "Disable shell/exec in production builds.",
                            "Route the tool behind a human-in-the-loop gate.",
                            "Use a sandboxed runner with strict allowlists.",
                        ],
                    )
                )

    # No unpinned model IDs in prod
    if env == "prod":
        for model in snapshot.find_nodes("Model"):
            version = model.metadata.get("version") or ""
            deployment = model.metadata.get("deployment") or ""
            if not str(version).strip() and not str(deployment).strip():
                evidence = []
                evidence_key = model.metadata.get("evidence")
                if evidence_key:
                    evidence.append(str(evidence_key))
                violations.append(
                    GraphPolicyViolation(
                        id=f"model-unpinned-{model.id}",
                        severity="error",
                        message=f"Model {model.id} is not pinned to a version or deployment in prod.",
                        evidence=evidence,
                        suggested_fixes=[
                            "Reference a provider deployment ID or immutable alias.",
                            "Use a dated/model-versioned identifier instead of family names.",
                            "Register the model in an internal registry and pin by alias.",
                        ],
                    )
                )

    return violations
