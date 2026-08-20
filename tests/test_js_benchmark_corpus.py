from pathlib import Path

from aibom_inspector.benchmarking import load_cases


MANIFEST = Path(__file__).parents[1] / "benchmarks" / "javascript" / "manifest.json"


def test_js_benchmark_corpus_has_broad_labeled_coverage() -> None:
    cases = load_cases(MANIFEST)
    assert len(cases) >= 20

    categories = {case.category for case in cases}
    assert {
        "provider",
        "agent",
        "tool",
        "mcp",
        "taint",
        "privileged-operation",
        "clean-negative",
        "adversarial-negative",
    } <= categories

    adversarial = [case for case in cases if case.category == "adversarial-negative"]
    assert len(adversarial) >= 4
    assert all(not case.expected_detectors for case in adversarial)


def test_js_benchmark_corpus_keeps_clean_negative_cases_explicit() -> None:
    cases = load_cases(MANIFEST)
    clean = [case for case in cases if case.category == "clean-negative"]
    assert len(clean) >= 4
    assert all(not case.expected_detectors for case in clean)
