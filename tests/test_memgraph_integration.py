from __future__ import annotations

import os
from datetime import datetime

import pytest

from aibom_inspector.graph_store import (
    GraphRelationshipRecord,
    populate_graph_from_report,
)
from aibom_inspector.types import DependencyInfo, DependencyIssue, ModelInfo, ModelIssue, Report

pytestmark = pytest.mark.memgraph


def _memgraph_store():
    if os.getenv("AIBOM_RUN_MEMGRAPH_TESTS") != "1":
        pytest.skip("Set AIBOM_RUN_MEMGRAPH_TESTS=1 and run examples/memgraph/docker-compose.yml to enable Memgraph integration tests.")
    try:
        import neo4j  # noqa: F401
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"Memgraph optional dependency is unavailable: {exc}")
    from aibom_inspector.memgraph_store import MemgraphGraphStore

    return MemgraphGraphStore()


def _representative_report() -> Report:
    return Report(
        dependencies=[
            DependencyInfo(
                name="torch",
                version="2.0.0",
                source="requirements.txt",
                license="BSD-3-Clause",
                issues=[
                    DependencyIssue(
                        "CVE-2026-0001 affects torch",
                        severity="high",
                        code="CVE-2026-0001",
                    ),
                    DependencyIssue(
                        "Shared dependency finding A",
                        severity="medium",
                        code="DEP-FINDING-A",
                    ),
                    DependencyIssue(
                        "Shared dependency finding B",
                        severity="medium",
                        code="DEP-FINDING-B",
                    ),
                ],
            )
        ],
        models=[
            ModelInfo(
                identifier="org/model-x",
                source="huggingface",
                license="apache-2.0",
                base_models=["base/model"],
                training_sources=["internal-dataset"],
                issues=[
                    ModelIssue(
                        "CVE-2026-0002 affects model-x",
                        severity="high",
                        code="CVE-2026-0002",
                    )
                ],
            )
        ],
        generated_at=datetime(2026, 1, 1),
    )


def test_memgraph_queries_read_back_persisted_graph_data() -> None:
    writer = _memgraph_store()
    writer.clear()
    populate_graph_from_report(writer, _representative_report())
    writer.upsert_relationship(GraphRelationshipRecord("Model:org/model-x", "Dependency:torch", "USES_DEPENDENCY"))
    writer.close()

    reader = _memgraph_store()
    try:
        # Clear the in-memory mirror to prove reads come from Memgraph.
        reader.nodes.clear()
        reader.relationships.clear()

        assert [node.id for node in reader.models_affected_by_vulnerability("CVE-2026-0001")] == [
            "Model:org/model-x"
        ]
        assert [node.id for node in reader.models_affected_by_vulnerability("CVE-2026-0002")] == [
            "Model:org/model-x"
        ]
        assert [node.id for node in reader.models_depending_on_package("torch")] == ["Model:org/model-x"]

        chain = reader.explain_finding("CVE-2026-0001")
        assert chain is not None
        assert any(node.id == "Finding:CVE-2026-0001" for node in chain.nodes)
        assert any(node.id == "Dependency:torch" for node in chain.nodes)

        assert reader.common_dependencies_for_findings() == {
            "Dependency:torch": ["Finding:CVE-2026-0001", "Finding:DEP-FINDING-A", "Finding:DEP-FINDING-B"]
        }
    finally:
        reader.clear()
        reader.close()


def test_report_to_memgraph_to_vulnerability_traversal_e2e() -> None:
    store = _memgraph_store()
    store.clear()
    try:
        populate_graph_from_report(store, _representative_report())
        store.nodes.clear()
        store.relationships.clear()

        models = store.models_affected_by_vulnerability("CVE-2026-0002")
        assert [model.properties["identifier"] for model in models] == ["org/model-x"]
    finally:
        store.clear()
        store.close()
