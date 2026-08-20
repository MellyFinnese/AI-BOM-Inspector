from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from typing import Iterable

from .js_analysis import JSEvidence, JSAnalysis, scan_javascript


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

    alias_map = {local: target for local, target in index.aliases}
    changed = True
    while changed:
        changed = False
        for local, target in alias_map.items():
            if target in provider_aliases and local not in provider_aliases:
                provider_aliases.add(local)
                changed = True
            if target in agent_aliases and local not in agent_aliases:
                agent_aliases.add(local)
                changed = True

    seen = {(f.detector_id, f.file, f.line, f.symbol) for f in findings}

    def add_finding(detector_id: str, kind: str, match: re.Match[str], symbol: str, confidence: float, role: str | None) -> None:
        line = _line(text, match.start())
        key = (detector_id, file, line, symbol)
        if key in seen:
            return
        seen.add(key)
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
        node_id = f"{file}:{line}:{kind}:{symbol}"
        nodes[node_id] = {"id": node_id, "kind": kind, "symbol": symbol, "file": file}

    for alias in sorted(agent_aliases):
        for match in re.finditer(rf"\bnew\s+{re.escape(alias)}\s*\(\s*\{{", text):
            add_finding("JS-AI-004", "agent", match, alias, 0.97, "ai-agent")

    for alias in sorted(provider_aliases):
        for match in re.finditer(
            rf"\b{re.escape(alias)}\.(?:responses|chat\.completions|messages)\.(?:create|stream)\s*\(",
            text,
        ):
            add_finding("JS-AI-002", "model_call", match, f"{alias}.model-call", 0.96, "provider-client")

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

    return JSAnalysis(
        base.files_scanned,
        tuple(findings),
        tuple(nodes.values()),
        tuple({"source": s, "relationship": r, "target": t} for s, r, t in sorted(edges)),
    )


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
            candidates = (
                source_file,
                source_file + ".ts",
                source_file + ".tsx",
                source_file + ".js",
                source_file + ".jsx",
                str(PurePosixPath(source_file) / "index.ts"),
                str(PurePosixPath(source_file) / "index.js"),
            )
            for candidate in candidates:
                key = (candidate, local if symbol == "default" else symbol)
                target = export_index.get(key)
                if target:
                    edges.add(
                        (
                            f"{candidate}:export:{target[1]}",
                            "IMPORTED_AS",
                            f"{consumer.file}:import:{local}",
                        )
                    )
                    break
    return tuple({"source": s, "relationship": r, "target": t} for s, r, t in sorted(edges))


def semantic_scan_javascript(root: str | Path, *, max_files: int = 5000, max_bytes: int = 1_000_000) -> JSAnalysis:
    base = scan_javascript(root, max_files=max_files, max_bytes=max_bytes)
    path = Path(root).resolve()
    if path.is_file():
        text = path.read_text(encoding="utf-8", errors="replace")
        return augment_with_alias_findings(text, file=path.name, base=base)

    findings = list(base.findings)
    nodes = list(base.nodes)
    edge_set = {(edge["source"], edge["relationship"], edge["target"]) for edge in base.edges}
    indexes: list[SemanticIndex] = []

    for current in sorted(path.rglob("*")):
        if not current.is_file() or current.suffix.lower() not in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}:
            continue
        if any(part in {"node_modules", ".git", "dist", "build", ".next", "coverage"} for part in current.parts):
            continue
        try:
            if current.stat().st_size > max_bytes:
                continue
            text = current.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        relative = str(current.relative_to(path))
        indexes.append(index_javascript(text, file=relative))
        result = augment_with_alias_findings(
            text,
            file=relative,
            base=JSAnalysis(1, tuple(f for f in base.findings if f.file == relative), tuple(n for n in base.nodes if n.get("file") == relative), tuple(e for e in base.edges if e.get("source", "").startswith(f"{relative}:"))),
        )
        findings.extend(f for f in result.findings if (f.detector_id, f.file, f.line, f.symbol) not in {(x.detector_id, x.file, x.line, x.symbol) for x in base.findings})
        nodes.extend(result.nodes)
        edge_set.update((e["source"], e["relationship"], e["target"]) for e in result.edges)

    edge_set.update((e["source"], e["relationship"], e["target"]) for e in build_cross_file_edges(indexes))
    dedup_findings = {(f.detector_id, f.file, f.line, f.symbol): f for f in findings}
    dedup_nodes = {n["id"]: n for n in nodes}
    return JSAnalysis(base.files_scanned, tuple(dedup_findings.values()), tuple(dedup_nodes.values()), tuple({"source": s, "relationship": r, "target": t} for s, r, t in sorted(edge_set)))