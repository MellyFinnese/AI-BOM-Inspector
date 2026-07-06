import json
from pathlib import Path

from aibom_inspector.runtime_trace import load_runtime_trace, trace_python


def test_runtime_trace_captures_provider_sdk_call(tmp_path: Path) -> None:
    script = tmp_path / "app.py"
    script.write_text(
        """
import sys
import types

openai = types.ModuleType("openai")

class Completions:
    def create(self, **kwargs):
        return {"ok": True}

class Chat:
    def __init__(self):
        self.completions = Completions()

openai.chat = Chat()
sys.modules["openai"] = openai

import openai

openai.chat.completions.create(model="gpt-4o-mini", messages=[])
"""
    )

    trace = trace_python(script, [])

    assert "gpt-4o-mini" in trace.observed_models
    assert any(
        call.get("provider") == "openai"
        and call.get("model") == "gpt-4o-mini"
        and call.get("call", "").endswith("chat.completions.create")
        for call in trace.observed_ai_calls
    )


def test_load_runtime_trace_accepts_observed_ai_calls(tmp_path: Path) -> None:
    path = tmp_path / "trace.json"
    path.write_text(
        json.dumps(
            {
                "trace_mode": "python-monkeypatch",
                "captured_at": "2026-07-06T00:00:00",
                "command": ["app.py"],
                "imported_modules": ["openai"],
                "observed_models": ["gpt-4o-mini"],
                "observed_ai_calls": [
                    {
                        "provider": "openai",
                        "call": "openai.chat.completions.create",
                        "model": "gpt-4o-mini",
                    }
                ],
                "observed_dependencies": ["openai"],
                "observed_env": [],
                "notes": [],
            }
        )
    )

    trace = load_runtime_trace(path)

    assert trace.observed_ai_calls[0]["call"] == "openai.chat.completions.create"
