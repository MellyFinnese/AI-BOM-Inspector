"""Memgraph adapter for the optional GraphStore interface."""

from __future__ import annotations

import os
from typing import Any

from .graph_store import (
    GraphNodeRecord,
    GraphRelationshipRecord,
    GraphStoreError,
    InMemoryGraphStore,
    RelationshipChain,
    _node_id,
)

_ALLOWED_REL_TYPES = {
    "CONTAINS",
    "DECLARED_LICENSE",
    "AFFECTED_BY",
    "EVIDENCED_BY",
    "DERIVED_FROM",
    "TRAINED_ON",
    "USES_DEPENDENCY",
    "USES_MODEL",
    "OWNED_BY",
    "GOVERNED_BY",
}


class MemgraphGraphStore(InMemoryGraphStore):
    """Bolt/Cypher-backed store for the optional graph POC.

    Writes are mirrored in memory only to keep generic store counters available
    to existing CLI output. Domain read methods below query Memgraph directly so
    integration tests can verify persisted graph data rather than the mirror.
    """

    def __init__(self, uri: str | None = None, user: str | None = None, password: str | None = None) -> None:
        super().__init__()
        self.uri = uri or os.getenv("AIBOM_MEMGRAPH_URI", "bolt://localhost:7687")
        self.user = user if user is not None else os.getenv("AIBOM_MEMGRAPH_USER", "")
        self.password = password if password is not None else os.getenv("AIBOM_MEMGRAPH_PASSWORD", "")

        # Pool sizing/config for async driver
        self._pool_size = int(os.getenv("AIBOM_MEMGRAPH_POOL_SIZE", "10"))

        try:
            from neo4j import GraphDatabase  # type: ignore
        except ImportError as exc:
            raise GraphStoreError("Memgraph support requires the optional 'neo4j' package.") from exc

        # create sync driver for CLI/legacy code
        try:
            auth = (self.user, self.password) if self.user or self.password else None
            self._driver = GraphDatabase.driver(self.uri, auth=auth)
            # verify connectivity for sync driver
            self._driver.verify_connectivity()
        except Exception as exc:
            raise GraphStoreError(f"Could not connect to Memgraph at {self.uri}.") from exc

        # attempt to create an async driver if available (neo4j.AsyncGraphDatabase)
        self._async_driver = None
        try:
            from neo4j import AsyncGraphDatabase  # type: ignore

            try:
                # create async driver with a connection pool size
                self._async_driver = AsyncGraphDatabase.driver(
                    self.uri,
                    auth=auth,
                    # Allow driver to configure pools via this argument if supported
                    max_connection_pool_size=self._pool_size,
                )
            except TypeError:
                # older neo4j versions may not accept pool args; fall back to driver() call
                self._async_driver = AsyncGraphDatabase.driver(self.uri, auth=auth)
        except Exception:
            # async driver not available or failed to initialize; that's okay — async APIs will be unavailable
            self._async_driver = None

    def close(self) -> None:
        """Close sync driver and attempt to close async driver if present.

        For CLI use the sync driver is closed immediately. If an async driver exists and an
        event loop is running we schedule its close; otherwise we run it to completion.
        """
        try:
            self._driver.close()
        except Exception:
            pass

        if self._async_driver:
            # Async close: if an event loop is running, create a task; otherwise run to completion.
            import asyncio

            try:
                loop = asyncio.get_running_loop()
                # schedule close in background
                loop.create_task(self._async_driver.close())
            except RuntimeError:
                # no running loop
                try:
                    asyncio.run(self._async_driver.close())
                except Exception:
                    # swallow errors on close
                    pass

    def clear(self) -> None:
        self.nodes.clear()
        self.relationships.clear()
        self._run_write("MATCH (n:GraphEntity) DETACH DELETE n")

    def upsert_node(self, node: GraphNodeRecord) -> None:
        super().upsert_node(node)
        self._run_write(
            "MERGE (n:GraphEntity {id: $id}) SET n.label = $label, n += $properties",
            id=node.id,
            label=node.label,
            properties=node.properties,
        )

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
        self._run_write(
            query,
            source_id=relationship.source_id,
            target_id=relationship.target_id,
            properties=relationship.properties,
        )

    def get_node(self, node_id: str) -> GraphNodeRecord | None:
        records = self._run_read(
            "MATCH (n:GraphEntity {id: $id}) RETURN n LIMIT 1",
            id=node_id,
        )
        if not records:
            return None
        return _record_to_node(records[0]["n"])

    def relationships_from(
        self, source_id: str, relationship_type: str | None = None
    ) -> list[GraphRelationshipRecord]:
        if relationship_type is not None and relationship_type not in _ALLOWED_REL_TYPES:
            raise ValueError(f"Unsupported relationship type: {relationship_type}")
        rel_fragment = f":{relationship_type}" if relationship_type else ""
        records = self._run_read(
            f"MATCH (a:GraphEntity {{id: $id}})-[r{rel_fragment}]->(b:GraphEntity) RETURN a, r, b",
            id=source_id,
        )
        return [_record_to_relationship(record["a"], record["r"], record["b"]) for record in records]

    def relationships_to(
        self, target_id: str, relationship_type: str | None = None
    ) -> list[GraphRelationshipRecord]:
        if relationship_type is not None and relationship_type not in _ALLOWED_REL_TYPES:
            raise ValueError(f"Unsupported relationship type: {relationship_type}")
        rel_fragment = f":{relationship_type}" if relationship_type else ""
        records = self._run_read(
            f"MATCH (a:GraphEntity)-[r{rel_fragment}]->(b:GraphEntity {{id: $id}}) RETURN a, r, b",
            id=target_id,
        )
        return [_record_to_relationship(record["a"], record["r"], record["b"]) for record in records]

    def models_affected_by_vulnerability(self, vulnerability_id: str) -> list[GraphNodeRecord]:
        records = self._run_read(
            """
            MATCH (m:GraphEntity {label: 'Model'})-[:AFFECTED_BY]->(:GraphEntity {id: $vulnerability_id})
            RETURN DISTINCT m
            UNION
            MATCH (m:GraphEntity {label: 'Model'})-[:USES_DEPENDENCY]->(:GraphEntity)-[:AFFECTED_BY]->(:GraphEntity {id: $vulnerability_id})
            RETURN DISTINCT m
            """,
            vulnerability_id=_node_id("Vulnerability", vulnerability_id),
        )
        return [_record_to_node(record["m"]) for record in records]

    def models_depending_on_package(self, package_name: str) -> list[GraphNodeRecord]:
        records = self._run_read(
            """
            MATCH (m:GraphEntity {label: 'Model'})-[:USES_DEPENDENCY]->(:GraphEntity {id: $dependency_id})
            RETURN DISTINCT m
            """,
            dependency_id=_node_id("Dependency", package_name),
        )
        return [_record_to_node(record["m"]) for record in records]

    def explain_finding(self, finding_id: str) -> RelationshipChain | None:
        records = self._run_read(
            """
            MATCH p=(:GraphEntity {id: $finding_id})-[*1..6]-(n:GraphEntity)
            RETURN p
            LIMIT 25
            """,
            finding_id=_node_id("Finding", finding_id),
        )
        if not records:
            return None
        nodes: dict[str, GraphNodeRecord] = {}
        relationships: dict[tuple[str, str, str], GraphRelationshipRecord] = {}
        for record in records:
            path = record["p"]
            for node in path.nodes:
                node_record = _record_to_node(node)
                nodes[node_record.id] = node_record
            for relationship in path.relationships:
                start = _record_to_node(relationship.start_node)
                end = _record_to_node(relationship.end_node)
                rel_record = GraphRelationshipRecord(
                    source_id=start.id,
                    target_id=end.id,
                    type=relationship.type,
                    properties={key: relationship[key] for key in relationship.keys()},
                )
                relationships[(rel_record.source_id, rel_record.target_id, rel_record.type)] = rel_record
        return RelationshipChain(nodes=list(nodes.values()), relationships=list(relationships.values()))

    def common_dependencies_for_findings(self) -> dict[str, list[str]]:
        records = self._run_read(
            """
            MATCH (f:GraphEntity {label: 'Finding'})-[:EVIDENCED_BY]->(d:GraphEntity {label: 'Dependency'})
            WITH d, collect(DISTINCT f.id) AS findings
            WHERE size(findings) > 1
            RETURN d.id AS dependency_id, findings
            """
        )
        return {record["dependency_id"]: sorted(record["findings"]) for record in records}

    def _run_write(self, query: str, **parameters: Any) -> None:
        """Synchronous write for CLI and existing callers."""
        with self._driver.session() as session:
            session.execute_write(lambda tx: tx.run(query, **parameters).consume())

    def _run_read(self, query: str, **parameters: Any) -> list[Any]:
        """Synchronous read for CLI and existing callers."""
        with self._driver.session() as session:
            return session.execute_read(lambda tx: list(tx.run(query, **parameters)))

    # Async helpers for non-blocking web/service usage. These require the optional
    # async driver (neo4j.AsyncGraphDatabase). They return the same payloads as
    # the synchronous counterparts but should be awaited by async callers.
    async def run_write_async(self, query: str, **parameters: Any) -> None:
        if not self._async_driver:
            raise GraphStoreError("Async neo4j driver unavailable; install neo4j>=5.x")

        async def _tx_run(tx, q, params):
            cursor = await tx.run(q, **params)
            # consume to ensure write applied
            await cursor.consume()

        async with self._async_driver.session() as session:
            await session.execute_write(_tx_run, query, parameters)

    async def run_read_async(self, query: str, **parameters: Any) -> list[Any]:
        if not self._async_driver:
            raise GraphStoreError("Async neo4j driver unavailable; install neo4j>=5.x")

        async def _tx_run_list(tx, q, params):
            cursor = await tx.run(q, **params)
            results = []
            async for rec in cursor:
                results.append(rec)
            return results

        async with self._async_driver.session() as session:
            return await session.execute_read(_tx_run_list, query, parameters)


def _record_to_node(node: Any) -> GraphNodeRecord:
    properties = dict(node)
    node_id = str(properties.pop("id"))
    label = str(properties.pop("label"))
    return GraphNodeRecord(node_id, label, properties)


def _record_to_relationship(start_node: Any, relationship: Any, end_node: Any) -> GraphRelationshipRecord:
    start = _record_to_node(start_node)
    end = _record_to_node(end_node)
    return GraphRelationshipRecord(
        source_id=start.id,
        target_id=end.id,
        type=relationship.type,
        properties={key: relationship[key] for key in relationship.keys()},
    )
