from aibom_inspector.behavioral_drift import compare_analyses
from aibom_inspector.js_analysis import analyze_javascript


def test_detects_ts_ai_usage_and_prompt_sink():
    result = analyze_javascript(
        'import { generateText } from "ai";\n'
        'const x = await generateText({ model: "gpt-4.1", prompt: "hi" });\n'
    )
    ids = {item.detector_id for item in result.findings}
    assert "JS-AI-001" in ids
    assert "JS-AI-003" in ids
    assert "JS-PROMPT-001" in ids


def test_detects_new_reachable_path_as_drift():
    baseline = analyze_javascript(
        'export function handler(req) { return req.body; }\n'
    )
    candidate = analyze_javascript(
        'export function handler(req) {\n'
        '  const prompt = req.body;\n'
        '  const agent = new Agent({ instructions: prompt, tools: [runShell] });\n'
        '  child_process.exec(input);\n'
        '}\n'
    )
    diff = compare_analyses(baseline, candidate)
    assert diff["edges_added"] >= 1
    assert diff["impact_path_added"] is True
