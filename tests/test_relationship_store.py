from __future__ import annotations

from pathlib import Path

from aibom_inspector.relationship_store import Relationship, RelationshipStore


def test_relationship_store_handles_batched_edges_and_paths(tmp_path: Path) -> None:
    path = tmp_path / "relationships.sqlite"
    edges = [
        Relationship("pkg:a", "pkg:b", "DEPENDS_ON"),
        Relationship("pkg:b", "model:c", "DEPENDS_ON", {"environment": "prod"}),
        Relationship("pkg:a", "pkg:b", "DEPENDS_ON"),
    ]
    with RelationshipStore(path) as store:
        assert store.bulk_insert(edges, batch_size=2) == 3
        assert store.count() == 2
        assert [item.target for item in store.dependencies_of("pkg:a")] == ["pkg:b"]
        assert store.shortest_path("pkg:a", "model:c") == ["pkg:a", "pkg:b", "model:c"]
