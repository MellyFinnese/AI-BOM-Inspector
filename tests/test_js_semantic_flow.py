from pathlib import Path

from aibom_inspector.js_semantics import index_javascript, semantic_scan_javascript


def test_alias_agent_and_provider_detection() -> None:
    result = semantic_scan_javascript_from_text(
        'import { Agent as SecureAgent } from "openai";\n'
        'import OpenAIClient from "openai";\n'
        'const client = OpenAIClient;\n'
        'const agent = new SecureAgent({ instructions: "ok" });\n'
        'client.responses.create({ model: "gpt-4.1" });\n'
    )
    detector_ids = {item.detector_id for item in result.findings}
    assert "JS-AI-004" in detector_ids
    assert "JS-AI-002" in detector_ids


def test_cross_file_index_records_exports_and_imports() -> None:
    exported = index_javascript(
        'export const userPrompt = request.body;\n',
        file="lib/prompts.ts",
    )
    consumer = index_javascript(
        'import { userPrompt as prompt } from "./lib/prompts";\n',
        file="app/agent.ts",
    )
    assert ("userPrompt", "userPrompt") in exported.exports
    assert ("./lib/prompts", "userPrompt", "prompt") in consumer.imports


def test_semantic_directory_scan_adds_alias_evidence(tmp_path: Path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "agent.ts").write_text(
        'import { Agent as SecureAgent } from "openai";\n'
        'export const run = () => new SecureAgent({ instructions: "trusted" });\n',
        encoding="utf-8",
    )
    result = semantic_scan_javascript(app)
    assert any(item.detector_id == "JS-AI-004" for item in result.findings)


def semantic_scan_javascript_from_text(text: str):
    from aibom_inspector.js_analysis import analyze_javascript
    from aibom_inspector.js_semantics import augment_with_alias_findings

    base = analyze_javascript(text, file="<memory>")
    return augment_with_alias_findings(text, file="<memory>", base=base)
