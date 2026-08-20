from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Relationship:
    source: str
    target: str
    relation: str
    metadata: dict[str, str] | None = None


class RelationshipStore:
    """Disk-backed relationship index for million-scale dependency graphs.

    SQLite WAL mode provides a durable spillover path when keeping every
    relationship in Python memory would be too expensive. The schema is
    intentionally backend-neutral so records can later be projected into
    Memgraph/Neo4j or another graph service.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, timeout=30)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=NORMAL")
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS relationships ("
            "source TEXT NOT NULL, target TEXT NOT NULL, relation TEXT NOT NULL, metadata TEXT, "
            "PRIMARY KEY(source, target, relation))"
        )
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_rel_source ON relationships(source, relation)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_rel_target ON relationships(target, relation)")
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "RelationshipStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def bulk_insert(self, relationships: Iterable[Relationship], *, batch_size: int = 10_000) -> int:
        if batch_size <= 0:
            raise ValueError("batch_size must be positive")
        count = 0
        batch: list[tuple[str, str, str, str | None]] = []
        for item in relationships:
            metadata = None
            if item.metadata:
                metadata = "&".join(f"{key}={item.metadata[key]}" for key in sorted(item.metadata))
            batch.append((item.source, item.target, item.relation, metadata))
            if len(batch) >= batch_size:
                self._insert_batch(batch)
                count += len(batch)
                batch.clear()
        if batch:
            self._insert_batch(batch)
            count += len(batch)
        return count

    def _insert_batch(self, batch: list[tuple[str, str, str, str | None]]) -> None:
        self.connection.executemany(
            "INSERT OR IGNORE INTO relationships(source, target, relation, metadata) VALUES (?, ?, ?, ?)",
            batch,
        )
        self.connection.commit()

    def dependencies_of(self, source: str) -> Iterator[Relationship]:
        rows = self.connection.execute(
            "SELECT source, target, relation, metadata FROM relationships WHERE source = ? ORDER BY target, relation",
            (source,),
        )
        yield from (Relationship(source, target, relation, _decode_metadata(metadata)) for source, target, relation, metadata in rows)

    def dependents_of(self, target: str) -> Iterator[Relationship]:
        rows = self.connection.execute(
            "SELECT source, target, relation, metadata FROM relationships WHERE target = ? ORDER BY source, relation",
            (target,),
        )
        yield from (Relationship(source, target, relation, _decode_metadata(metadata)) for source, target, relation, metadata in rows)

    def shortest_path(self, source: str, target: str, *, max_depth: int = 12) -> list[str] | None:
        if source == target:
            return [source]
        frontier = [source]
        parents: dict[str, str | None] = {source: None}
        for _ in range(max_depth):
            next_frontier: list[str] = []
            for node in frontier:
                for relation in self.dependencies_of(node):
                    if relation.target in parents:
                        continue
                    parents[relation.target] = node
                    if relation.target == target:
                        return _reconstruct_path(parents, target)
                    next_frontier.append(relation.target)
            frontier = next_frontier
            if not frontier:
                break
        return None

    def count(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM relationships").fetchone()[0])


def _decode_metadata(value: str | None) -> dict[str, str] | None:
    if not value:
        return None
    result: dict[str, str] = {}
    for item in value.split("&"):
        key, separator, raw = item.partition("=")
        if separator:
            result[key] = raw
    return result or None


def _reconstruct_path(parents: dict[str, str | None], target: str) -> list[str]:
    path: list[str] = []
    current: str | None = target
    while current is not None:
        path.append(current)
        current = parents[current]
    path.reverse()
    return path
