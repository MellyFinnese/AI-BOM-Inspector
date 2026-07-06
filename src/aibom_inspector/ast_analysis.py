from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class StaticModelEvidence:
    identifier: str
    provider: str | None
    evidence: str
    language: str
    call: str | None = None


MODEL_REFERENCE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(gpt-[\w.-]+)\b", re.IGNORECASE), "openai"),
    (re.compile(r"\b(o[1-9](?:-[\w.-]+)?)\b", re.IGNORECASE), "openai"),
    (re.compile(r"\b(claude[-\w.]*)\b", re.IGNORECASE), "anthropic"),
    (re.compile(r"\b((?:meta-)?llama[-/\w.]*)\b", re.IGNORECASE), "meta"),
)

PYTHON_MODEL_CALLS = {
    "from_pretrained": "huggingface",
    "pipeline": "huggingface",
    "create": None,
    "parse": None,
    "stream": None,
    "complete": None,
    "invoke": None,
    "predict": None,
    "generate_content": "google",
}

PROVIDER_BY_IMPORT = {
    "openai": "openai",
    "anthropic": "anthropic",
    "google.generativeai": "google",
    "vertexai": "google",
    "boto3": "aws",
    "langchain": "langchain",
    "transformers": "huggingface",
}

JS_PROVIDER_HINTS = {
    "openai": "openai",
    "anthropic": "anthropic",
    "generativeai": "google",
    "vertexai": "google",
    "bedrock": "aws",
}

MODEL_KEYS = {"model", "model_id", "modelName", "model_name", "pretrained_model_name_or_path"}


def _safe_read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        try:
            return path.read_text(errors="ignore")
        except Exception:
            return ""


def _provider_from_identifier(identifier: str, fallback: str | None = None) -> str | None:
    for pattern, provider in MODEL_REFERENCE_PATTERNS:
        if pattern.search(identifier):
            return provider
    if "/" in identifier:
        return "huggingface"
    return fallback


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _literal_value(node: ast.AST, constants: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                resolved = _literal_value(value.value, constants)
                if resolved is None:
                    return None
                parts.append(resolved)
            else:
                return None
        return "".join(parts)
    return None


def _python_import_providers(tree: ast.AST) -> dict[str, str]:
    providers: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                provider = PROVIDER_BY_IMPORT.get(alias.name) or PROVIDER_BY_IMPORT.get(root)
                if provider:
                    providers[alias.asname or root] = provider
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            provider = PROVIDER_BY_IMPORT.get(node.module) or PROVIDER_BY_IMPORT.get(root)
            if provider:
                for alias in node.names:
                    providers[alias.asname or alias.name] = provider
    return providers


def _python_constants(tree: ast.AST) -> dict[str, str]:
    constants: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            value = _literal_value(node.value, constants)
            if value is None:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    constants[target.id] = value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
            value = _literal_value(node.value, constants)
            if value is not None:
                constants[node.target.id] = value
    return constants


def _provider_from_python_call(call_name: str, import_providers: dict[str, str], default: str | None) -> str | None:
    parts = call_name.split(".")
    for part in parts:
        if part in import_providers:
            return import_providers[part]
    lowered = call_name.lower()
    for hint, provider in PROVIDER_BY_IMPORT.items():
        if hint.split(".")[0] in lowered:
            return provider
    return default


def analyze_python_source(path: Path, source: str) -> list[StaticModelEvidence]:
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return []

    constants = _python_constants(tree)
    import_providers = _python_import_providers(tree)
    evidence: list[StaticModelEvidence] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            for pattern, provider in MODEL_REFERENCE_PATTERNS:
                for match in pattern.findall(node.value):
                    identifier = match if isinstance(match, str) else match[0]
                    evidence.append(
                        StaticModelEvidence(
                            identifier=identifier,
                            provider=provider,
                            evidence=f"{path}:{getattr(node, 'lineno', 1)}",
                            language="python",
                        )
                    )

        if not isinstance(node, ast.Call):
            continue

        call_name = _call_name(node.func)
        terminal_name = call_name.rsplit(".", 1)[-1]
        default_provider = PYTHON_MODEL_CALLS.get(terminal_name)
        if terminal_name not in PYTHON_MODEL_CALLS:
            continue

        provider = _provider_from_python_call(call_name, import_providers, default_provider)
        candidates: list[str] = []
        if terminal_name in {"from_pretrained", "pipeline"} and node.args:
            value = _literal_value(node.args[0], constants)
            if value:
                candidates.append(value)
        for keyword in node.keywords:
            if keyword.arg in MODEL_KEYS:
                value = _literal_value(keyword.value, constants)
                if value:
                    candidates.append(value)

        for identifier in candidates:
            evidence.append(
                StaticModelEvidence(
                    identifier=identifier,
                    provider=_provider_from_identifier(identifier, provider),
                    evidence=f"{path}:{getattr(node, 'lineno', 1)}",
                    language="python",
                    call=call_name,
                )
            )

    return _dedupe(evidence)


def _strip_js_comments(source: str) -> str:
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.DOTALL)


def _js_string_value(raw: str, constants: dict[str, str]) -> str | None:
    raw = raw.strip()
    if raw in constants:
        return constants[raw]
    if len(raw) >= 2 and raw[0] in {"'", '"', "`"} and raw[-1] == raw[0]:
        inner = raw[1:-1]
        if "${" not in inner:
            return inner
    return None


def _js_constants(source: str) -> dict[str, str]:
    constants: dict[str, str] = {}
    assignment = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(['\"`])([^'\"`\n]+)\2")
    for match in assignment.finditer(source):
        constants[match.group(1)] = match.group(3)
    return constants


def _provider_from_js_context(call_name: str, source: str, fallback: str | None = None) -> str | None:
    lowered = f"{call_name}\n{source[:4000]}".lower()
    for hint, provider in JS_PROVIDER_HINTS.items():
        if hint in lowered:
            return provider
    return fallback


def analyze_javascript_source(path: Path, source: str) -> list[StaticModelEvidence]:
    cleaned = _strip_js_comments(source)
    constants = _js_constants(cleaned)
    evidence: list[StaticModelEvidence] = []

    for pattern, provider in MODEL_REFERENCE_PATTERNS:
        for match in pattern.findall(cleaned):
            identifier = match if isinstance(match, str) else match[0]
            evidence.append(
                StaticModelEvidence(
                    identifier=identifier,
                    provider=provider,
                    evidence=str(path),
                    language="javascript",
                )
            )

    object_model = re.compile(
        r"(?P<call>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\((?P<args>[^)]{0,2000})\)",
        re.DOTALL,
    )
    property_model = re.compile(
        r"(?:model|model_id|modelName|model_name)\s*:\s*(?P<value>['\"`][^'\"`\n]+['\"`]|[A-Za-z_$][\w$]*)"
    )
    for call_match in object_model.finditer(cleaned):
        call_name = call_match.group("call")
        args = call_match.group("args")
        if not any(token in call_name.lower() for token in {"openai", "anthropic", "chat", "completion", "message", "response", "generate", "pipeline"}):
            continue
        provider = _provider_from_js_context(call_name, cleaned)
        for prop_match in property_model.finditer(args):
            identifier = _js_string_value(prop_match.group("value"), constants)
            if identifier:
                evidence.append(
                    StaticModelEvidence(
                        identifier=identifier,
                        provider=_provider_from_identifier(identifier, provider),
                        evidence=str(path),
                        language="javascript",
                        call=call_name,
                    )
                )

    direct_model_arg = re.compile(
        r"\b(?:model|modelId|modelName)\s*\(\s*(?P<value>['\"`][^'\"`\n]+['\"`]|[A-Za-z_$][\w$]*)"
    )
    for match in direct_model_arg.finditer(cleaned):
        identifier = _js_string_value(match.group("value"), constants)
        if identifier:
            evidence.append(
                StaticModelEvidence(
                    identifier=identifier,
                    provider=_provider_from_identifier(identifier),
                    evidence=str(path),
                    language="javascript",
                    call="model",
                )
            )

    return _dedupe(evidence)


def _dedupe(items: Iterable[StaticModelEvidence]) -> list[StaticModelEvidence]:
    seen: set[tuple[str, str | None, str, str | None]] = set()
    result: list[StaticModelEvidence] = []
    for item in items:
        key = (item.identifier, item.provider, item.evidence, item.call)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def analyze_source_file(path: Path) -> list[StaticModelEvidence]:
    source = _safe_read(path)
    if not source:
        return []
    suffix = path.suffix.lower()
    if suffix == ".py":
        return analyze_python_source(path, source)
    if suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
        return analyze_javascript_source(path, source)
    return []


def discover_static_model_evidence(root: Path | str) -> list[StaticModelEvidence]:
    root_path = Path(root)
    evidence: list[StaticModelEvidence] = []
    for path in root_path.rglob("*"):
        if path.is_dir():
            continue
        if path.suffix.lower() in {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
            evidence.extend(analyze_source_file(path))
    return _dedupe(evidence)
