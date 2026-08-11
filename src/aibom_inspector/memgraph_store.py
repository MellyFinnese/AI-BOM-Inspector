"""Memgraph adapter for the optional GraphStore interface."""

from __future__ import annotations

import os
from .graph_store import GraphNodeRecord, GraphRelationshipRecord, GraphStoreError, InMemoryGraphStore

_ALLOWED_REL_TYPES = {"CONTAINS", "DECLARED_LICENSE", "AFFECTED_BY", "EVIDENCED_BY", "DERIVED_FROM", "TRAINED_ON", "USES_DEPENDENCY", "USES_MODEL", "OWNED_BY", "GOVERNED_BY"}


class MemgraphGraphStore(InMemoryGraphStore):
    """Bolt/Cypher-backed store with in-memory query helpers for POC queries.

    The adapter writes to Memgraph when the optional ``neo4j`` package is installed.
    It also mirrors writes in memory so unit tests and POC queries can run without
    requiring graph-specific result mapping for every traversal.
    """

    def __init__(self, uri: str | None = None, user: str | None = None, password: str | None = None) -> None:
        super().__init__()
        self.uri = uri or os.getenv("AIBOM_MEMGRAPH_URI", "bolt://localhost:7687")
        self.user = user if user is not None else os.getenv("AIBOM_MEMGRAPH_USER", "")
        self.password = password if password is not None else os.getenv("AIBOM_MEMGRAPH_PASSWORD", "")
        try:
            from neo4j import GraphDatabase  # type: ignore
        except ImportError as exc:
            raise GraphStoreError("Memgraph support requires the optional 'neo4j' package.") from exc
        try:
            auth = (self.user, self.password) if self.user or self.password else None
            self._driver = GraphDatabase.driver(self.uri, auth=auth)
            self._driver.verify_connectivity()
        except Exception as exc:
            raise GraphStoreError(f"Could not connect to Memgraph at {self.uri}.") from exc

    def close(self) -> None:
        self._driver.close()

    def upsert_node(self, node: GraphNodeRecord) -> None:
        super().upsert_node(node)
        with self._driver.session() as session:
            session.run("MERGE (n:GraphEntity {id: $id}) SET n.label = $label, n += $properties", id=node.id, label=node.label, properties=node.properties)

    def upsert_relationship(self, relationship: GraphRelationshipRecord) -> None:
        if relationship.type not in _ALLOWED_REL_TYPES:
            raise ValueError(f"Unsupported relationship type: {relationship.type}")
        super().upsert_relationship(relationship)
        query = f"""
        MATCH (a:GraphEntity {{id: $source_id}})
        MATCH (b:GraphEntity {{id: $target_id}})
        MERGE (a)-[r:{relationship.type}]->(b)
        SET r += $properties
        """
        with self._driver.session() as session:
            session.run(query, source_id=relationship.source_id, target_id=relationship.target_id, properties=relationship.properties)
