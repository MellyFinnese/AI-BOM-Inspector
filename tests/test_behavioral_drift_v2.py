from aibom_inspector.behavioral_drift import compare_analyses
from aibom_inspector.js_analysis import JSAnalysis


def _analysis(*, edges: list[tuple[str, str, str]], kinds: dict[str, str]) -> JSAnalysis:
    nodes = tuple(
        {"id": node_id, "kind": kind, "symbol": node_id.rsplit(":", 1)[-1], "file": "fixture.ts"}
        for node_id, kind in kinds.items()
    )
    edge_payload = tuple(
        {"source": source, "relationship": relationship, "target": target}
        for source, relationship, target in edges
    )
    return JSAnalysis(files_scanned=1, findings=(), nodes=nodes, edges=edge_payload)


def test_reports_new_input_to_privileged_operation_path() -> None:
    source = "fixture.ts:1:input:http-input"
    prompt = "fixture.ts:2:prompt-sink:prompt"
    op = "fixture.ts:3:privileged-operation:child_process.exec"

    baseline = _analysis(
        edges=[(source, "FLOWS_TO", prompt)],
        kinds={source: "input", prompt: "prompt-sink"},
    )
    candidate = _analysis(
        edges=[
            (source, "FLOWS_TO", prompt),
            (prompt, "CAN_REACH", op),
        ],
        kinds={source: "input", prompt: "prompt-sink", op: "privileged-operation"},
    )

    diff = compare_analyses(baseline, candidate)

    assert diff["impact_path_added"] is True
    assert diff["impact_severity"] == "critical"
    assert diff["impact_paths_added"] == 1
    assert diff["impact_paths"][0]["nodes"] == [source, prompt, op]


def test_does_not_report_unchanged_path_as_drift() -> None:
    source = "fixture.ts:1:input:http-input"
    prompt = "fixture.ts:2:prompt-sink:prompt"
    tool = "fixture.ts:3:tool:tool-binding"
    edges = [(source, "FLOWS_TO", prompt), (prompt, "CAN_REACH", tool)]
    kinds = {source: "input", prompt: "prompt-sink", tool: "tool"}

    diff = compare_analyses(_analysis(edges=edges, kinds=kinds), _analysis(edges=edges, kinds=kinds))

    assert diff["impact_path_added"] is False
    assert diff["impact_paths_added"] == 0
    assert diff["impact_paths_removed"] == 0


def test_reports_removed_impact_path() -> None:
    source = "fixture.ts:1:input:http-input"
    prompt = "fixture.ts:2:prompt-sink:prompt"
    op = "fixture.ts:3:privileged-operation:fs.writeFile"
    baseline = _analysis(
        edges=[(source, "FLOWS_TO", prompt), (prompt, "CAN_REACH", op)],
        kinds={source: "input", prompt: "prompt-sink", op: "privileged-operation"},
    )
    candidate = _analysis(
        edges=[(source, "FLOWS_TO", prompt)],
        kinds={source: "input", prompt: "prompt-sink"},
    )

    diff = compare_analyses(baseline, candidate)

    assert diff["impact_path_added"] is False
    assert diff["impact_paths_removed"] == 1
