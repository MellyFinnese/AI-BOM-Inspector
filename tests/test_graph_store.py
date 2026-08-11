from __future__ import annotations

from datetime import datetime

import pytest

from aibom_inspector.graph_store import (
    GraphNodeRecord,
    GraphRelationshipRecord,
    GraphStoreError,
    InMemoryGraphStore,
    populate_graph_from_report,
)
from aibom_inspector.memgraph_store import MemgraphGraphStore
from aibom_inspector.types import DependencyInfo, DependencyIssue, ModelInfo, ModelIssue, Report


def _report() -> Report:
    return Report(
        dependencies=[
            DependencyInfo(
                name="torch",
                version="2.0.0",
                source="requirements.txt",
                license="BSD-3-Clause",
                issues=[DependencyIssue("CVE-2026-0001 affects torch", severity="high", code="CVE-2026-0001")],
            )
        ],
        models=[
            ModelInfo(
                identifier="org/model-x",
                source="huggingface",
                license="apache-2.0",
                base_models=["base/model"],
                training_sources=["internal-dataset"],
                issues=[ModelIssue("known advisory", severity="medium", code="MODEL-ADV", metadata={"cve": "CVE-2026-0002"})],
            ),
            ModelInfo(identifier="org/no-provenance", source="huggingface"),
        ],
        generated_at=datetime(2026, 1, 1),
    )


def test_in_memory_upserts_nodes_and_relationships_without_duplicates() -> None:
    store = InMemoryGraphStore()
    store.upsert_node(GraphNodeRecord("Dependency:torch", "Dependency", {"version": "1"}))
    store.upsert_node(GraphNodeRecord("Dependency:torch", "Dependency", {"license": "BSD"}))
    store.upsert_relationship(GraphRelationshipRecord("Model:m", "Dependency:torch", "USES_DEPENDENCY"))
    store.upsert_relationship(GraphRelationshipRecord("Model:m", "Dependency:torch", "USES_DEPENDENCY", {"evidence": "test"}))

    assert store.get_node("Dependency:torch").properties == {"version": "1", "license": "BSD"}
    assert len(store.relationships) == 1
    assert store.relationships[("Model:m", "Dependency:torch", "USES_DEPENDENCY")].properties["evidence"] == "test"


def test_malformed_node_and_relationship_input_is_rejected() -> None:
    store = InMemoryGraphStore()
    with pytest.raises(ValueError):
        store.upsert_node(GraphNodeRecord("", "Dependency"))
    with pytest.raises(ValueError):
        store.upsert_relationship(GraphRelationshipRecord("a", "", "USES_DEPENDENCY"))


def test_populate_graph_from_report_creates_supported_entities() -> None:
    store = InMemoryGraphStore()
    populate_graph_from_report(store, _report())

    assert store.get_node("Dependency:torch") is not None
    assert store.get_node("Model:org/model-x") is not None
    assert store.get_node("License:apache-2.0") is not None
    assert store.get_node("TrainingSource:internal-dataset") is not None
    assert store.get_node("Vulnerability:CVE-2026-0001") is not None


def test_vulnerability_impact_and_missing_provenance_queries() -> None:
    store = InMemoryGraphStore()
    populate_graph_from_report(store, _report())
    store.upsert_relationship(GraphRelationshipRecord("Model:org/model-x", "Dependency:torch", "USES_DEPENDENCY"))

    assert [n.properties["identifier"] for n in store.models_affected_by_vulnerability("CVE-2026-0001")] == ["org/model-x"]
    assert [n.properties["identifier"] for n in store.models_depending_on_package("torch")] == ["org/model-x"]
    assert {n.properties["identifier"] for n in store.models_with_missing_provenance()} == {"org/no-provenance"}


def test_downstream_application_owner_and_explanation_chain() -> None:
    store = InMemoryGraphStore()
    populate_graph_from_report(store, _report())
    store.upsert_node(GraphNodeRecord("Application:api", "Application", {"environment": "prod"}))
    store.upsert_node(GraphNodeRecord("Owner:team-a", "Owner", {"name": "team-a"}))
    store.upsert_relationship(GraphRelationshipRecord("Application:api", "Model:org/model-x", "USES_MODEL"))
    store.upsert_relationship(GraphRelationshipRecord("Application:api", "Owner:team-a", "OWNED_BY"))
    store.upsert_relationship(GraphRelationshipRecord("Model:org/model-x", "Dependency:torch", "USES_DEPENDENCY"))

    assert [n.id for n in store.downstream_applications_for_dependency("torch")] == ["Application:api"]
    assert [n.id for n in store.owners_for_affected_applications("CVE-2026-0001")] == ["Owner:team-a"]
    chain = store.explain_finding("CVE-2026-0001")
    assert chain is not None
    assert any(node.id == "Dependency:torch" for node in chain.nodes)


def test_empty_missing_relationship_data_returns_empty_lists() -> None:
    store = InMemoryGraphStore()
    assert store.models_affected_by_vulnerability("CVE-DOES-NOT-EXIST") == []
    assert store.downstream_applications_for_dependency("missing") == []
    assert store.explain_finding("missing") is None


def test_common_dependencies_for_findings() -> None:
    store = InMemoryGraphStore()
    store.upsert_node(GraphNodeRecord("Dependency:shared", "Dependency"))
    for finding in ("Finding:a", "Finding:b"):
        store.upsert_node(GraphNodeRecord(finding, "Finding"))
        store.upsert_relationship(GraphRelationshipRecord(finding, "Dependency:shared", "EVIDENCED_BY"))
    assert store.common_dependencies_for_findings() == {"Dependency:shared": ["Finding:a", "Finding:b"]}


def test_memgraph_connection_failure_is_wrapped() -> None:
    with pytest.raises(GraphStoreError):
        MemgraphGraphStore(uri="bolt://127.0.0.1:1")
