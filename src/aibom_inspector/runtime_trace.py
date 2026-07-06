from __future__ import annotations

import builtins
import runpy
import sys
from datetime import datetime
from pathlib import Path
from types import ModuleType
from typing import Callable, Iterable

from .types import RuntimeTrace
from .parsers import ParserError, parse_runtime_trace_file


AI_CALL_NAMES = {
    "create",
    "parse",
    "stream",
    "complete",
    "invoke",
    "predict",
    "generate_content",
    "embed",
    "embed_documents",
    "embed_query",
}

def _model_identifier(args: tuple, kwargs: dict) -> str | None:
    identifier = None
    if args:
        identifier = args[0]
    identifier = identifier or kwargs.get("model") or kwargs.get("model_id") or kwargs.get(
        "pretrained_model_name_or_path"
    )
    if identifier:
        return str(identifier)
    return None


def _wrap_callable(
    target: object,
    name: str,
    record_model: Callable[[str], None],
    record_call: Callable[[dict[str, str]], None] | None = None,
    *,
    provider: str | None = None,
    call_path: str | None = None,
) -> Callable[[], None]:
    original = getattr(target, name, None)
    if not callable(original):
        return lambda: None

    def wrapper(*args, **kwargs):
        identifier = _model_identifier(args, kwargs)
        if identifier:
            record_model(str(identifier))
        if record_call:
            call = {
                "provider": provider or "unknown",
                "call": call_path or name,
            }
            if identifier:
                call["model"] = str(identifier)
            record_call(call)
        return original(*args, **kwargs)

    setattr(target, name, wrapper)

    def restore():
        setattr(target, name, original)

    return restore


def _patch_transformers(module: ModuleType, record: Callable[[str], None]) -> list[Callable[[], None]]:
    restores: list[Callable[[], None]] = []
    for class_name in ("AutoModel", "AutoModelForCausalLM", "AutoTokenizer", "AutoProcessor"):
        target = getattr(module, class_name, None)
        if target:
            restores.append(_wrap_callable(target, "from_pretrained", record))
    if getattr(module, "pipeline", None):
        restores.append(_wrap_callable(module, "pipeline", record))
    return restores


def _patch_torch(module: ModuleType, record: Callable[[str], None]) -> list[Callable[[], None]]:
    restores: list[Callable[[], None]] = []
    hub = getattr(module, "hub", None)
    if hub and getattr(hub, "load", None):
        restores.append(_wrap_callable(hub, "load", record))
    return restores


def _patch_tensorflow(module: ModuleType, record: Callable[[str], None]) -> list[Callable[[], None]]:
    restores: list[Callable[[], None]] = []
    keras = getattr(module, "keras", None)
    models = getattr(keras, "models", None) if keras else None
    if models and getattr(models, "load_model", None):
        restores.append(_wrap_callable(models, "load_model", record))
    return restores


def _patch_module(module: ModuleType, record: Callable[[str], None]) -> list[Callable[[], None]]:
    if module.__name__ == "transformers":
        return _patch_transformers(module, record)
    if module.__name__ == "torch":
        return _patch_torch(module, record)
    if module.__name__ == "tensorflow":
        return _patch_tensorflow(module, record)
    return []


def _provider_name(module_name: str) -> str | None:
    root = module_name.split(".")[0]
    if root in {"openai", "anthropic", "vertexai", "boto3", "langchain"}:
        return root
    if root == "google":
        return "google"
    return None


def _patch_ai_sdk_object(
    target: object,
    record_model: Callable[[str], None],
    record_call: Callable[[dict[str, str]], None],
    *,
    provider: str,
    prefix: str,
    seen: set[int],
    depth: int = 0,
) -> list[Callable[[], None]]:
    if depth > 3 or id(target) in seen:
        return []
    seen.add(id(target))

    restores: list[Callable[[], None]] = []
    for name in dir(target):
        if name.startswith("_"):
            continue
        try:
            value = getattr(target, name)
        except Exception:
            continue
        call_path = f"{prefix}.{name}" if prefix else name
        if callable(value) and name in AI_CALL_NAMES:
            restores.append(
                _wrap_callable(
                    target,
                    name,
                    record_model,
                    record_call,
                    provider=provider,
                    call_path=call_path,
                )
            )
            continue
        if isinstance(value, (str, bytes, int, float, bool, tuple, list, dict, set)):
            continue
        value_module = getattr(value, "__module__", "")
        value_provider = _provider_name(value_module) or provider
        if value_provider == provider:
            restores.extend(
                _patch_ai_sdk_object(
                    value,
                    record_model,
                    record_call,
                    provider=provider,
                    prefix=call_path,
                    seen=seen,
                    depth=depth + 1,
                )
            )
    return restores


def _patch_ai_sdk_module(
    module: ModuleType,
    record_model: Callable[[str], None],
    record_call: Callable[[dict[str, str]], None],
) -> list[Callable[[], None]]:
    provider = _provider_name(module.__name__)
    if not provider:
        return []
    return _patch_ai_sdk_object(
        module,
        record_model,
        record_call,
        provider=provider,
        prefix=module.__name__,
        seen=set(),
    )


def trace_python(script: Path, args: Iterable[str]) -> RuntimeTrace:
    imported_modules: set[str] = set()
    observed_models: list[str] = []
    observed_ai_calls: list[dict[str, str]] = []
    restore_hooks: list[Callable[[], None]] = []
    patched_modules: set[str] = set()

    original_import = builtins.__import__

    def _record_model(identifier: str) -> None:
        observed_models.append(identifier)

    def _record_ai_call(call: dict[str, str]) -> None:
        observed_ai_calls.append(call)

    def hooked_import(name, globals=None, locals=None, fromlist=(), level=0):  # type: ignore[override]
        module = original_import(name, globals, locals, fromlist, level)
        root = name.split(".")[0]
        imported_modules.add(root)
        try:
            if isinstance(module, ModuleType):
                if module.__name__ not in patched_modules:
                    restore_hooks.extend(_patch_module(module, _record_model))
                    restore_hooks.extend(_patch_ai_sdk_module(module, _record_model, _record_ai_call))
                    patched_modules.add(module.__name__)
        except Exception:
            pass
        return module

    builtins.__import__ = hooked_import  # type: ignore[assignment]

    original_argv = sys.argv
    sys.argv = [str(script), *args]
    try:
        runpy.run_path(str(script), run_name="__main__")
    finally:
        builtins.__import__ = original_import  # type: ignore[assignment]
        for restore in restore_hooks:
            try:
                restore()
            except Exception:
                pass
        sys.argv = original_argv

    return RuntimeTrace(
        trace_mode="python-monkeypatch",
        captured_at=datetime.utcnow(),
        command=[str(script), *args],
        imported_modules=sorted(imported_modules),
        observed_models=sorted(set(observed_models)),
        observed_ai_calls=sorted(
            ({tuple(sorted(call.items())): call for call in observed_ai_calls}).values(),
            key=lambda call: (call.get("provider", ""), call.get("call", ""), call.get("model", "")),
        ),
        observed_dependencies=sorted(imported_modules),
        notes=[
            "Runtime trace captured via in-process import hooks, model-load hooks, and provider SDK call hooks.",
            "Use network-level telemetry for coverage beyond supported Python SDK APIs.",
        ],
    )


def load_runtime_trace(path: Path) -> RuntimeTrace:
    try:
        data = parse_runtime_trace_file(path).model_dump()
    except ParserError as exc:
        raise RuntimeError(str(exc)) from exc
    return RuntimeTrace(
        trace_mode=data.get("trace_mode", "unknown"),
        captured_at=datetime.fromisoformat(data.get("captured_at"))
        if data.get("captured_at")
        else datetime.utcnow(),
        command=list(data.get("command", [])),
        imported_modules=list(data.get("imported_modules", [])),
        observed_models=list(data.get("observed_models", [])),
        observed_ai_calls=[dict(entry) for entry in data.get("observed_ai_calls", [])],
        observed_dependencies=list(data.get("observed_dependencies", [])),
        observed_env=list(data.get("observed_env", [])),
        notes=list(data.get("notes", [])),
    )
