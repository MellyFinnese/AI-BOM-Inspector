from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Iterable

from .js_analysis import JSEvidence, JSAnalysis


AI_MODULES = {"openai", "@anthropic-ai/sdk", "ai"}
AGENT_SYMBOLS = {"Agent", "OpenAI", "Anthropic"}


@dataclass(frozen=True)
class SemanticIndex:
    file: str
    imports: tuple[tuple[str, str, str], ...]
    exports: tuple[tuple[str, str], ...]
    aliases: tuple[tuple[str, str], ...]


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _snippet(text: str, start: int, width: int = 180) -> str:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    if line_end == -1:
        line_end = len(text)
    return " ".join(text[line_start:line_end].strip().split())[:width]


def index_javascript(text: str, *, file: str) -> SemanticIndex:
    imports: list[tuple[str, str, str]] = []
    exports: list[tuple[str, str]] = []
    aliases: list[tuple[str, str]] = []

    for match in re.finditer(
        r"import\s+([A-Za-z_$][\w$]*)\s+from\s+[\"']([^\"']+)[\"']",
        text,
    ):
        imports.append((match.group(2), "default", match.group(1)))

    for match in re.finditer(
        r"import\s*\{([^}]+)\}\s*from\s*[\"']([^\"']+)[\"']",
        text,
    ):
        for item in match.group(1).split(","):
            parts = re.split(r"\s+as\s+", item.strip())
            symbol = parts[0].strip()
            local = parts[-1].strip()
            if symbol:
                imports.append((match.group(2), symbol, local))

    for match in re.finditer(
        r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*[\"']([^\"']+)[\"']\s*\)",
        text,
    ):
        imports.append((match.group(2), "default", match.group(1)))

    for match in re.finditer(
        r"export\s+(?:const|let|var|function|class)\s+([A-Za-z_$][\w$]*)",
        text,
    ):
        exports.append((match.group(1), match.group(1)))

    for match in re.finditer(
        r"export\s*\{\s*([A-Za-z_$][\w$]*)\s+as\s+([A-Za-z_$][\w$]*)\s*\}",
        text,
    ):
        exports.append((match.group(2), match.group(1)))

    # Local aliases are intentionally narrow: they capture explicit symbol renames,
    # which is safer than pretending to perform full JavaScript name resolution.
    for match in re.finditer(
        r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*;",
        text,
    ):
        aliases.append((match.group(1), match.group(2)))

    return SemanticIndex(file, tuple(imports), tuple(exports), tuple(aliases))


def augment_with_alias_findings(text: str, *, file: str, base: JSAnalysis) -> JSAnalysis:
    findings = list(base.findings)
    nodes = {node["id"]: node for node in base.nodes}
    edges = {(edge["source"], edge["relationship"], edge["target"]) for edge in base.edges}
    index = index_javascript(text, file=file)

    agent_aliases: set[str] = set()
    provider_aliases: set[str] = set()
    for module, symbol, local in index.imports:
        if module in AI_MODULES:
            provider_aliases.add(local)
            if symbol in AGENT_SYMBOLS:
                agent_aliases.add(local)
        if symbol == "Agent":
            agent_aliases.add(local)

    seen = {(f.detector_id, f.file, f.line, f.symbol) for f in findings}

    def add_finding(detector_id: str, kind: str, match: re.Match[str], symbol: str, confidence: float, role: str | None) -> None:
        line = _line(text, match.start())
        key = (detector_id, file, line, symbol)
        if key in seen:
            return
        seen.add(key)
        evidence = JSEvidence(
            detector_id=detector_id,
            kind=kind,
            file=file,
            line=line,
            symbol=symbol,
            evidence=_snippet(text, match.start()),
            confidence=confidence,
            role=role,
        )
        findings.append(evidence)
        node_id = f"{file}:{line}:{kind}:{symbol}"
        nodes[node_id] = {"id": node_id, "kind": kind, "symbol": symbol, "file": file}

    for alias in sorted(agent_aliases):
        pattern = re.compile(rf"\bnew\s+{re.escape(alias)}\s*\(\s*\{{")
        for match in pattern.finditer(text):
            add_finding("JS-AI-004", "agent", match, alias, 0.97, "ai-agent")

    # Alias-aware model calls catch renamed provider clients that the lexical rules
    # cannot identify by the literal names `openai`, `anthropic`, or `client`.
    for alias in sorted(provider_aliases):
        pattern = re.compile(rf"\b{re.escape(alias)}\.(?:responses|chat\.completions|messages)\.(?:create|stream)\s*\(")
        for match in pattern.finditer(text):
            add_finding("JS-AI-002", "model_call", match, f"{alias}.model-call", 0.96, "provider-client")

    # A simple same-file variable-flow edge: an untrusted source assigned to a
    # variable which is later consumed as a prompt/instructions value.
    assignments = re.findall(
        r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)",
        text,
    )
    source_vars: set[str] = set()
    prompt_vars: set[str] = set()
    for name, value in assignments:
        if re.search(r"\b(?:req|request|event)\.(?:body|query|params|headers)\b|\bprocess\.argv\b|\bprocess\.env\.", value, re.I):
            source_vars.add(name)
        if re.search(r"prompt|instruction|system|message", name, re.I):
            prompt_vars.add(name)
    for src_var in source_vars:
        for prompt_var in prompt_vars:
            source_match = re.search(rf"\b{re.escape(src_var)}\b", text)
            prompt_match = re.search(rf"\b{re.escape(prompt_var)}\b", text)
            if source_match and prompt_match:
                source_id = f"{file}:{_line(text, source_match.start())}:variable:{src_var}"
                prompt_id = f"{file}:{_line(text, prompt_match.start())}:variable:{prompt_var}"
                nodes.setdefault(source_id, {"id": source_id, "kind": "variable", "symbol": src_var, "file": file})
                nodes.setdefault(prompt_id, {"id": prompt_id, "kind": "variable", "symbol": prompt_var, "file": file})
                edges.add((source_id, "FLOWS_TO", prompt_id))

    return JSAnalysis(base.files_scanned, tuple(findings), tuple(nodes.values()), tuple({"source": s, "relationship": r, "target": t} for s, r, t in sorted(edges)))


def build_cross_file_edges(indexes: Iterable[SemanticIndex]) -> tuple[dict[str, str], ...]:
    all_indexes = tuple(indexes)
    export_index: dict[tuple[str, str], tuple[str, str]] = {}
    for index in all_indexes:
        for exported, local in index.exports:
            export_index[(index.file, exported)] = (index.file, local)

    edges: set[tuple[str, str, str]] = set()
    for consumer in all_indexes:
        for module, symbol, local in consumer.imports:
            if not module.startswith("."):
                continue
            source_file = str(PurePosixPath(consumer.file).parent.joinpath(module))
            source_candidates = (source_file, source_file + ".ts", source_file + ".tsx", source_file + ".js", source_file + ".jsx", str(PurePosixPath(source_file) / "index.ts"), str(PurePosixPath(source_file) / "index.js"))
            for candidate in source_candidates:
                key = (candidate, local if symbol == "default" else symbol)
                target = export_index.get(key)
                if target:
                    source_id = f"{candidate}:export:{target[1]}"
                    target_id = f"{consumer.file}:import:{local}"
                    edges.add((source_id, "IMPORTED_AS", target_id))
                    break
    return tuple({"source": s, "relationship": r, "target": t} for s, r, t in sorted(edges))
