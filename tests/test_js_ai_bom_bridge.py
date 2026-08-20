from aibom_inspector.ai_assets import AIBOMDocument
from aibom_inspector.js_ai_bom_bridge import bridge_js_analysis_to_aibom
from aibom_inspector.js_analysis import analyze_javascript


def test_bridges_ai_code_nodes_and_impact_paths_into_aibom_metadata():
    analysis = analyze_javascript(
        'export function handler(req) {\n'
        '  const prompt = req.body.prompt;\n'
        '  const agent = new Agent({ instructions: prompt, tools: [runShell] });\n'
        '  child_process.exec(req.body.command);\n'
        '}\n'
    )
    document = bridge_js_analysis_to_aibom(AIBOMDocument(), analysis)
    kinds = {asset.kind for asset in document.assets}
    assert {"agent", "prompt", "tool"}.issubset(kinds)
    assert document.metadata["code_graph"]["node_count"] == len(analysis.nodes)
    assert document.metadata["code_impact_paths"]
