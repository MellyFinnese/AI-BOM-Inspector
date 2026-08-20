from aibom_inspector.attack_paths import discover_impact_paths, diff_impact_paths
from aibom_inspector.js_analysis import analyze_javascript


def _candidate() -> str:
    return (
        'export function handler(req) {\n'
        '  const prompt = req.body.prompt;\n'
        '  const agent = new Agent({ instructions: prompt, tools: [runShell] });\n'
        '  child_process.exec(req.body.command);\n'
        '}\n'
    )


def test_discovers_bounded_input_to_side_effect_path():
    result = analyze_javascript(_candidate())
    paths = discover_impact_paths(result)
    assert paths
    assert any(path.source.endswith(":input:http-input") for path in paths)
    assert any(path.target.endswith(":privileged-operation:child_process.exec") for path in paths)
    assert all(path.severity == "critical" for path in paths)


def test_diff_reports_new_and_removed_paths():
    baseline = analyze_javascript('export function handler(req) { return req.body.prompt; }\n')
    candidate = analyze_javascript(_candidate())
    added = diff_impact_paths(baseline, candidate)
    assert added["impact_path_added"] is True
    assert added["impact_path_count_added"] >= 1

    removed = diff_impact_paths(candidate, baseline)
    assert removed["impact_path_count_removed"] >= 1
