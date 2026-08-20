from aibom_inspector.graph_payload import build_graph_payload
from aibom_inspector.js_analysis import analyze_javascript


def test_graph_payload_is_backend_neutral_and_complete():
    analysis = analyze_javascript('export function handler(req) { return req.body.prompt; }\n')
    payload = build_graph_payload(analysis)
    assert payload["schema_version"] == "aibom-js-graph.v1"
    assert len(payload["nodes"]) == len(analysis.nodes)
    assert len(payload["edges"]) == len(analysis.edges)
