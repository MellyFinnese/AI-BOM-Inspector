from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


JS_EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
DEFAULT_IGNORES = {"node_modules", ".git", "dist", "build", ".next", "coverage"}


@dataclass(frozen=True)
class JSEvidence:
    detector_id: str
    kind: str
    file: str
    line: int
    symbol: str
    evidence: str
    confidence: float
    role: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class JSAnalysis:
    files_scanned: int
    findings: tuple[JSEvidence, ...]
    nodes: tuple[dict[str, str], ...]
    edges: tuple[dict[str, str], ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "js-analysis.v1",
            "files_scanned": self.files_scanned,
            "findings": [item.to_dict() for item in self.findings],
            "nodes": list(self.nodes),
            "edges": list(self.edges),
        }


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _snippet(text: str, start: int, width: int = 180) -> str:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    if line_end == -1:
        line_end = len(text)
    return " ".join(text[line_start:line_end].strip().split())[:width]


def _stable_id(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def _mask_non_code(text: str) -> str:
    """Replace comments and string contents with spaces while preserving offsets/newlines."""
    chars = list(text)
    i = 0
    n = len(chars)
    state = "code"
    quote = ""
    while i < n:
        if state == "code":
            if text.startswith("//", i):
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "line-comment"
                continue
            if text.startswith("/*", i):
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "block-comment"
                continue
            if text[i] in {"'", '"', "`"}:
                quote = text[i]
                chars[i] = " "
                i += 1
                state = "string"
                continue
            i += 1
            continue

        if state == "line-comment":
            if text[i] == "\n":
                state = "code"
            else:
                chars[i] = " "
            i += 1
            continue

        if state == "block-comment":
            if text.startswith("*/", i):
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "code"
            else:
                if text[i] != "\n":
                    chars[i] = " "
                i += 1
            continue

        # string / template literal. This deliberately treats the literal body as non-code;
        # template interpolation is therefore conservative rather than attempting full parsing.
        if text[i] == "\\" and i + 1 < n:
            if text[i] != "\n":
                chars[i] = " "
            if text[i + 1] != "\n":
                chars[i + 1] = " "
            i += 2
            continue
        if text[i] == quote:
            chars[i] = " "
            i += 1
            state = "code"
            continue
        if text[i] != "\n":
            chars[i] = " "
        i += 1
    return "".join(chars)


def _mask_static_dead_if_false(code: str) -> str:
    """Blank statically unreachable `if (false) { ... }` blocks, preserving offsets."""
    chars = list(code)
    for match in re.finditer(r"\bif\s*\(\s*false\s*\)\s*\{", code, re.IGNORECASE):
        depth = 0
        in_block = False
        i = match.start()
        while i < len(code):
            if code[i] == "{":
                depth += 1
                in_block = True
            elif code[i] == "}" and in_block:
                depth -= 1
                if depth == 0:
                    for j in range(match.start(), i + 1):
                        if chars[j] != "\n":
                            chars[j] = " "
                    break
            i += 1
    return "".join(chars)


def analyze_javascript(text: str, *, file: str = "<memory>") -> JSAnalysis:
    findings: list[JSEvidence] = []
    nodes: dict[str, dict[str, str]] = {}
    edges: set[tuple[str, str, str]] = set()
    code_mask = _mask_non_code(text)
    code = _mask_static_dead_if_false(code_mask)

    def add(detector_id: str, kind: str, match: re.Match[str], symbol: str, confidence: float, role: str | None = None) -> None:
        line = _line_of(text, match.start())
        findings.append(
            JSEvidence(
                detector_id=detector_id,
                kind=kind,
                file=file,
                line=line,
                symbol=symbol,
                evidence=_snippet(text, match.start()),
                confidence=confidence,
                role=role,
            )
        )
        node_key = f"{file}:{line}:{kind}:{symbol}"
        nodes[node_key] = {"id": node_key, "kind": kind, "symbol": symbol, "file": file}

    # Provider imports are matched against source text, but the match must begin in executable code.
    import_patterns = [
        ("JS-AI-001", r"(?:from\s+[\"'](openai|@anthropic-ai/sdk|ai)[\"']|require\(\s*[\"'](openai|@anthropic-ai/sdk|ai)[\"']\s*\))", "ai-sdk")
    ]
    for detector_id, pattern, symbol in import_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            if code_mask[match.start()] != " ":
                add(detector_id, "provider", match, symbol, 0.98)

    # Provider/model calls. The call receiver is intentionally identifier-agnostic; semantic analysis
    # later adds higher-confidence provider-specific aliases. This catches SDK clients such as
    # `client.messages.create`, `client.responses.create`, and `client.chat.completions.create`.
    for match in re.finditer(
        r"\b[A-Za-z_$][\w$]*\.(?:chat\.completions|responses|messages|generateText|streamText|generateObject)\s*\(",
        code,
        re.IGNORECASE,
    ):
        add("JS-AI-002", "model_call", match, "model-call", 0.92, role="provider-client")

    for match in re.finditer(r"\b(?:generateText|streamText|generateObject)\s*\(", code, re.IGNORECASE):
        add("JS-AI-003", "model_call", match, "vercel-ai-call", 0.92, role="model-call")

    for match in re.finditer(r"\bnew\s+Agent\s*\(\s*\{", code):
        add("JS-AI-004", "agent", match, "agent", 0.92, role="ai-agent")

    for match in re.finditer(r"\b(?:McpServer|MCPServer|Server)\s*\(", code):
        add("JS-AI-005", "mcp", match, "mcp-server", 0.92, role="mcp")

    # Common agent/tool declarations.
    tool_pattern = re.compile(r"\b(?:tools|tool|server\.tool|registerTool)\s*\(?\s*[\"'`]?([A-Za-z0-9_.:/-]+)?", re.IGNORECASE)
    for match in tool_pattern.finditer(code):
        symbol = match.group(1) or "tool-binding"
        add("JS-AGENT-001", "tool", match, symbol, 0.86, role="bound-tool")

    # Trust-boundary sources.
    source_patterns = [
        ("JS-TAINT-001", "http-input", r"\b(?:req|request|ctx\.request|event)\.(?:body|query|params|headers)\b"),
        ("JS-TAINT-002", "cli-input", r"\b(?:process\.argv|yargs|commander|cac)\b"),
        ("JS-TAINT-003", "env-input", r"\bprocess\.env\.[A-Z0-9_]+\b"),
        ("JS-TAINT-004", "retrieval-input", r"\b(?:retriever|vectorStore|similaritySearch|query\(.*embedding)\b"),
    ]
    source_nodes: list[str] = []
    for detector_id, kind, pattern in source_patterns:
        for match in re.finditer(pattern, code, re.IGNORECASE):
            add(detector_id, "input", match, kind, 0.88, role="untrusted-source")
            source_nodes.append(f"{file}:{_line_of(text, match.start())}:input:{kind}")

    # Prompt sinks. Capture likely argument identifiers/literals for stable graphing, not raw prompt content.
    prompt_pattern = re.compile(
        r"\b(?:instructions|system|systemPrompt|prompt|messages)\s*[:=]\s*(?:[\"'`]|\{|\[|[A-Za-z_$][\w$]*)",
        re.IGNORECASE,
    )
    prompt_nodes: list[str] = []
    for match in prompt_pattern.finditer(code):
        add("JS-PROMPT-001", "prompt-sink", match, "prompt", 0.91, role="privileged-instructions")
        prompt_nodes.append(f"{file}:{_line_of(text, match.start())}:prompt-sink:prompt")

    # Tool-capable sinks.
    op_pattern = re.compile(r"\b(?:child_process\.(?:exec|execFile|spawn)|fs\.(?:writeFile|rm|unlink)|fetch|axios\.(?:get|post|put|delete))\s*\(", re.IGNORECASE)
    op_nodes: list[str] = []
    for match in op_pattern.finditer(code):
        op = re.search(r"(?:child_process\.(?:exec|execFile|spawn)|fs\.(?:writeFile|rm|unlink)|fetch|axios\.(?:get|post|put|delete))", match.group(0), re.IGNORECASE)
        symbol = op.group(0) if op else "privileged-operation"
        add("JS-TOOL-001", "privileged-operation", match, symbol, 0.9, role="side-effect")
        op_nodes.append(f"{file}:{_line_of(text, match.start())}:privileged-operation:{symbol}")

    # Conservative same-file relationships: sources -> prompt sinks, prompt sinks -> tools.
    for src in source_nodes:
        for sink in prompt_nodes:
            edges.add((src, "FLOWS_TO", sink))
    for sink in prompt_nodes:
        for op in op_nodes:
            edges.add((sink, "CAN_REACH", op))

    return JSAnalysis(
        files_scanned=1,
        findings=tuple(findings),
        nodes=tuple(nodes.values()),
        edges=tuple({"source": s, "relationship": r, "target": t} for s, r, t in sorted(edges)),
    )


def scan_javascript(root: str | Path, *, max_files: int = 5000, max_bytes: int = 1_000_000) -> JSAnalysis:
    base = Path(root).resolve()
    if not base.exists():
        raise FileNotFoundError(base)
    paths: Iterable[Path]
    if base.is_file():
        paths = [base]
    else:
        paths = (p for p in base.rglob("*") if p.is_file() and p.suffix.lower() in JS_EXTENSIONS and not DEFAULT_IGNORES.intersection(p.parts))

    findings: list[JSEvidence] = []
    nodes: list[dict[str, str]] = []
    edges: list[dict[str, str]] = []
    scanned = 0
    for path in sorted(paths):
        if scanned >= max_files:
            break
        try:
            if path.stat().st_size > max_bytes:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        result = analyze_javascript(text, file=str(path.relative_to(base) if base.is_dir() else path.name))
        findings.extend(result.findings)
        nodes.extend(result.nodes)
        edges.extend(result.edges)
        scanned += 1
    return JSAnalysis(scanned, tuple(findings), tuple(nodes), tuple(edges))
