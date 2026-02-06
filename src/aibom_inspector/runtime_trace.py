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


def _wrap_callable(target: object, name: str, record: Callable[[str], None]) -> Callable[[], None]:
    original = getattr(target, name, None)
    if not callable(original):
        return lambda: None

    def wrapper(*args, **kwargs):
        identifier = None
        if args:
            identifier = args[0]
        identifier = identifier or kwargs.get("model") or kwargs.get("model_id") or kwargs.get(
            "pretrained_model_name_or_path"
        )
        if identifier:
            record(str(identifier))
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


def trace_python(script: Path, args: Iterable[str]) -> RuntimeTrace:
    imported_modules: set[str] = set()
    observed_models: list[str] = []
    restore_hooks: list[Callable[[], None]] = []

    original_import = builtins.__import__

    def _record_model(identifier: str) -> None:
        observed_models.append(identifier)

    def hooked_import(name, globals=None, locals=None, fromlist=(), level=0):  # type: ignore[override]
        module = original_import(name, globals, locals, fromlist, level)
        root = name.split(".")[0]
        imported_modules.add(root)
        try:
            if isinstance(module, ModuleType):
                restore_hooks.extend(_patch_module(module, _record_model))
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
        observed_dependencies=sorted(imported_modules),
        notes=[
            "Runtime trace captured via in-process import hooks and monkeypatching.",
            "Use LD_PRELOAD or interpreter-level tracing for coverage beyond Python APIs.",
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
        observed_dependencies=list(data.get("observed_dependencies", [])),
        observed_env=list(data.get("observed_env", [])),
        notes=list(data.get("notes", [])),
    )
