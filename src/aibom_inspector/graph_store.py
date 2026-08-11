"""Optional graph/context layer for AI-BOM scan reports.

The graph layer is deliberately separate from scoring. It persists and queries
relationships that already exist in ``Report`` payloads so callers can explain
and investigate risk findings without changing deterministic risk decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from .types import Report


@dataclass(frozen=True)
class GraphNodeRecord:
    id: str
    label: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GraphRelationshipRecord:
    source_id: str
    target_id: str
    type: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RelationshipChain:
    nodes: list[GraphNodeRecord]
    relationships: list[GraphRelationshipRecord]
    limitation: str | None = None


class GraphStoreError(RuntimeError):
    pass


class GraphStore(Protocol):
    def upsert_node(self, node: GraphNodeRecord) -> None: ...
    def upsert_relationship(self, relationship: GraphRelationshipRecord) -> None: ...
    def get_node(self, node_id: str) -> GraphNodeRecord | None: ...
    def relationships_from(self, source_id: str, relationship_type: str | None = None) -> list[GraphRelationshipRecord]: ...
    def relationships_to(self, target_id: str, relationship_type: str | None = None) -> list[GraphRelationshipRecord]: ...
    def models_affected_by_vulnerability(self, vulnerability_id: str) -> list[GraphNodeRecord]: ...
    def models_depending_on_package(self, package_name: str) -> list[GraphNodeRecord]: ...
    def downstream_applications_for_dependency(self, package_name: str) -> list[GraphNodeRecord]: ...
    def owners_for_affected_applications(self, vulnerability_id: str) -> list[GraphNodeRecord]: ...
    def models_with_missing_provenance(self) -> list[GraphNodeRecord]: ...
    def explain_finding(self, finding_id: str) -> RelationshipChain | None: ...
    def common_dependencies_for_findings(self) -> dict[str, list[str]]: ...


class InMemoryGraphStore:
    def __init__(self) -> None:
        self.nodes: dict[str, GraphNodeRecord] = {}
        self.relationships: dict[tuple[str, str, str], GraphRelationshipRecord] = {}

    def upsert_node(self, node: GraphNodeRecord) -> None:
        if not node.id or not node.label:
            raise ValueError("Graph nodes require non-empty id and label.")
        existing = self.nodes.get(node.id)
        if existing:
            self.nodes[node.id] = GraphNodeRecord(node.id, node.label, {**existing.properties, **node.properties})
        else:
            self.nodes[node.id] = node

    def upsert_relationship(self, relationship: GraphRelationshipRecord) -> None:
        if not relationship.source_id or not relationship.target_id or not relationship.type:
            raise ValueError("Graph relationships require source_id, target_id, and type.")
        key = (relationship.source_id, relationship.target_id, relationship.type)
        existing = self.relationships.get(key)
        if existing:
            self.relationships[key] = GraphRelationshipRecord(
                relationship.source_id,
                relationship.target_id,
                relationship.type,
                {**existing.properties, **relationship.properties},
            )
        else:
            self.relationships[key] = relationship

    def get_node(self, node_id: str) -> GraphNodeRecord | None:
        return self.nodes.get(node_id)

    def relationships_from(self, source_id: str, relationship_type: str | None = None) -> list[GraphRelationshipRecord]:
        return [r for r in self.relationships.values() if r.source_id == source_id and (relationship_type is None or r.type == relationship_type)]

    def relationships_to(self, target_id: str, relationship_type: str | None = None) -> list[GraphRelationshipRecord]:
        return [r for r in self.relationships.values() if r.target_id == target_id and (relationship_type is None or r.type == relationship_type)]

    def _nodes_from(self, source_id: str, relationship_type: str) -> list[GraphNodeRecord]:
        return [self.nodes[r.target_id] for r in self.relationships_from(source_id, relationship_type) if r.target_id in self.nodes]

    def _nodes_to(self, target_id: str, relationship_type: str) -> list[GraphNodeRecord]:
        return [self.nodes[r.source_id] for r in self.relationships_to(target_id, relationship_type) if r.source_id in self.nodes]

    def models_affected_by_vulnerability(self, vulnerability_id: str) -> list[GraphNodeRecord]:
        vuln_id = _node_id("Vulnerability", vulnerability_id)
        deps = self._nodes_to(vuln_id, "AFFECTED_BY")
        models: dict[str, GraphNodeRecord] = {}
        for dep in deps:
            for model in self._nodes_to(dep.id, "USES_DEPENDENCY"):
                models[model.id] = model
        for model in self._nodes_to(vuln_id, "AFFECTED_BY"):
            if model.label == "Model":
                models[model.id] = model
        return list(models.values())

    def models_depending_on_package(self, package_name: str) -> list[GraphNodeRecord]:
        return self._nodes_to(_node_id("Dependency", package_name), "USES_DEPENDENCY")

    def downstream_applications_for_dependency(self, package_name: str) -> list[GraphNodeRecord]:
        dep_id = _node_id("Dependency", package_name)
        apps: dict[str, GraphNodeRecord] = {}
        for app in self._nodes_to(dep_id, "USES_DEPENDENCY"):
            if app.label == "Application":
                apps[app.id] = app
        for model in self._nodes_to(dep_id, "USES_DEPENDENCY"):
            for app in self._nodes_to(model.id, "USES_MODEL"):
                apps[app.id] = app
        return list(apps.values())

    def owners_for_affected_applications(self, vulnerability_id: str) -> list[GraphNodeRecord]:
        owners: dict[str, GraphNodeRecord] = {}
        for model in self.models_affected_by_vulnerability(vulnerability_id):
            for app in self._nodes_to(model.id, "USES_MODEL"):
                for owner in self._nodes_from(app.id, "OWNED_BY"):
                    owners[owner.id] = owner
        return list(owners.values())

    def models_with_missing_provenance(self) -> list[GraphNodeRecord]:
        return [n for n in self.nodes.values() if n.label == "Model" and n.properties.get("provenance_status") in {"missing", "questionable"}]

    def explain_finding(self, finding_id: str) -> RelationshipChain | None:
        start = self.get_node(_node_id("Finding", finding_id))
        if not start:
            return None
        nodes = [start]
        rels: list[GraphRelationshipRecord] = []
        frontier = [start.id]
        seen = {start.id}
        for _ in range(6):
            next_frontier = []
            for node_id in frontier:
                for rel in self.relationships_from(node_id) + self.relationships_to(node_id):
                    other = rel.target_id if rel.source_id == node_id else rel.source_id
                    if other in seen or other not in self.nodes:
                        continue
                    seen.add(other)
                    rels.append(rel)
                    nodes.append(self.nodes[other])
                    next_frontier.append(other)
            frontier = next_frontier
        return RelationshipChain(nodes=nodes, relationships=rels)

    def common_dependencies_for_findings(self) -> dict[str, list[str]]:
        dep_to_findings: dict[str, list[str]] = {}
        for rel in self.relationships.values():
            if rel.type == "EVIDENCED_BY" and rel.target_id.startswith("Dependency:"):
                dep_to_findings.setdefault(rel.target_id, []).append(rel.source_id)
        return {dep: findings for dep, findings in dep_to_findings.items() if len(findings) > 1}


def _node_id(label: str, value: str) -> str:
    return f"{label}:{value.strip()}"


def _issue_vulnerability_ids(issue: Any) -> list[str]:
    values = []
    if issue.code and "CVE" in str(issue.code).upper():
        values.append(str(issue.code))
    for key in ("id", "cve", "cve_id", "osv_id", "advisory_id"):
        value = issue.metadata.get(key) if isinstance(issue.metadata, dict) else None
        if value:
            values.append(str(value))
    if "CVE-" in issue.message.upper():
        values.append(issue.message.split()[0].strip("[]"))
    return sorted(set(values))


def populate_graph_from_report(store: GraphStore, report: Report) -> None:
    report_id = _node_id("Report", (report.provenance or {}).get("git_commit") or report.generated_at.isoformat())
    store.upsert_node(GraphNodeRecord(report_id, "Report", {"score": report.stack_risk_score}))

    for dep in report.dependencies:
        dep_id = _node_id("Dependency", dep.name)
        store.upsert_node(GraphNodeRecord(dep_id, "Dependency", {"name": dep.name, "version": dep.version, "source": dep.source, "license": dep.license, "license_category": dep.license_category}))
        store.upsert_relationship(GraphRelationshipRecord(report_id, dep_id, "CONTAINS"))
        if dep.license:
            lic_id = _node_id("License", dep.license)
            store.upsert_node(GraphNodeRecord(lic_id, "License", {"name": dep.license, "category": dep.license_category}))
            store.upsert_relationship(GraphRelationshipRecord(dep_id, lic_id, "DECLARED_LICENSE"))
        for issue in dep.issues:
            finding_id = _node_id("Finding", issue.code or f"{dep.name}:{issue.message}")
            store.upsert_node(GraphNodeRecord(finding_id, "Finding", {"message": issue.message, "severity": issue.severity, "code": issue.code}))
            store.upsert_relationship(GraphRelationshipRecord(finding_id, dep_id, "EVIDENCED_BY"))
            for vuln in _issue_vulnerability_ids(issue):
                vuln_id = _node_id("Vulnerability", vuln)
                store.upsert_node(GraphNodeRecord(vuln_id, "Vulnerability", {"identifier": vuln}))
                store.upsert_relationship(GraphRelationshipRecord(dep_id, vuln_id, "AFFECTED_BY"))

    for model in report.models:
        model_id = _node_id("Model", model.identifier)
        provenance_status = "present" if model.training_sources and (model.base_models or model.fine_tuned_from) else "missing"
        store.upsert_node(GraphNodeRecord(model_id, "Model", {"identifier": model.identifier, "source": model.source, "license": model.license, "license_category": model.license_category, "provenance_status": provenance_status}))
        store.upsert_relationship(GraphRelationshipRecord(report_id, model_id, "CONTAINS"))
        for base in [*model.base_models, *model.fine_tuned_from]:
            base_id = _node_id("Model", base)
            store.upsert_node(GraphNodeRecord(base_id, "Model", {"identifier": base}))
            store.upsert_relationship(GraphRelationshipRecord(model_id, base_id, "DERIVED_FROM"))
        for source in model.training_sources:
            source_id = _node_id("TrainingSource", source)
            store.upsert_node(GraphNodeRecord(source_id, "TrainingSource", {"name": source}))
            store.upsert_relationship(GraphRelationshipRecord(model_id, source_id, "TRAINED_ON"))
        if model.license:
            lic_id = _node_id("License", model.license)
            store.upsert_node(GraphNodeRecord(lic_id, "License", {"name": model.license, "category": model.license_category}))
            store.upsert_relationship(GraphRelationshipRecord(model_id, lic_id, "DECLARED_LICENSE"))
        for issue in model.issues:
            finding_id = _node_id("Finding", issue.code or f"{model.identifier}:{issue.message}")
            store.upsert_node(GraphNodeRecord(finding_id, "Finding", {"message": issue.message, "severity": issue.severity, "code": issue.code}))
            store.upsert_relationship(GraphRelationshipRecord(finding_id, model_id, "EVIDENCED_BY"))
            for vuln in _issue_vulnerability_ids(issue):
                vuln_id = _node_id("Vulnerability", vuln)
                store.upsert_node(GraphNodeRecord(vuln_id, "Vulnerability", {"identifier": vuln}))
                store.upsert_relationship(GraphRelationshipRecord(model_id, vuln_id, "AFFECTED_BY"))
