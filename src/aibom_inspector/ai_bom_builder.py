from __future__ import annotations

from .ai_assets import (
    AIBOMDocument, AIAsset, AIRelationship, ArtifactIdentity, DatasetLineage,
    DeploymentContext, EvaluationEvidence, ModelVersion, TrainingProvenance,
    artifact_id_from_digest, stable_asset_id,
)
from .types_report import Report


def build_ai_bom(report: Report) -> AIBOMDocument:
    """Convert an existing scan report into a structured AI-BOM context graph."""
    assets: list[AIAsset] = []
    versions: list[ModelVersion] = []
    artifacts: list[ArtifactIdentity] = []
    provenance: list[TrainingProvenance] = []
    deployments: list[DeploymentContext] = []
    evaluations: list[EvaluationEvidence] = []
    relationships: list[AIRelationship] = []
    asset_ids: set[str] = set(); version_ids: set[str] = set(); artifact_ids: set[str] = set()
    prov_ids: set[str] = set(); deployment_ids: set[str] = set(); eval_ids: set[str] = set()
    edge_ids: set[tuple[str, str, str]] = set()

    def asset(kind: str, name: str, *, provider: str | None = None, source: str | None = None, metadata: dict | None = None) -> str:
        aid = stable_asset_id(kind, name, provider=provider)
        if aid not in asset_ids:
            assets.append(AIAsset(id=aid, kind=kind, name=name, provider=provider, source=source, metadata=metadata or {}))
            asset_ids.add(aid)
        return aid

    def edge(a: str, b: str, rel: str) -> None:
        key = (a, b, rel)
        if key not in edge_ids:
            relationships.append(AIRelationship(from_id=a, to_id=b, type=rel)); edge_ids.add(key)

    applications = {a.name: asset("deployment", a.name, provider=a.owner, source="application inventory", metadata={"environment": a.environment, "criticality": a.criticality, "data_sensitivity": a.data_sensitivity, "owner": a.owner}) for a in report.applications}
    model_versions: dict[str, str] = {}

    for model in report.models:
        mid = asset("model", model.identifier, provider=model.source, source="model inventory", metadata={"risk": model.risk_score, "trust_score": model.trust_score})
        mids = []
        for digest in model.hashes:
            d = str(digest).strip()
            if len(d) == 64 and all(c in "0123456789abcdefABCDEF" for c in d):
                aid = artifact_id_from_digest(d)
                if aid not in artifact_ids:
                    artifacts.append(ArtifactIdentity(id=aid, digest=d.lower(), media_type="application/octet-stream")); artifact_ids.add(aid)
                mids.append(aid); edge(mid, aid, "PACKAGED_AS")
        vv = model.last_updated.isoformat() if model.last_updated else "unknown"
        vid = stable_asset_id("model_version", model.identifier, vv, model.source); model_versions[model.identifier] = vid
        if vid not in version_ids:
            versions.append(ModelVersion(id=vid, model_id=mid, version=vv, provider=model.source, artifact_ids=mids)); version_ids.add(vid)
        edge(vid, mid, "VERSION_OF")

        dlines: list[DatasetLineage] = []
        for src in model.training_sources:
            did = asset("dataset", src, source="training provenance")
            dlines.append(DatasetLineage(dataset_id=did, source_uri=src)); edge(vid, did, "TRAINED_ON")
        parents: list[str] = []
        for parent in model.base_models + model.fine_tuned_from:
            pmid = asset("model", parent, source="lineage"); pvid = stable_asset_id("model_version", parent, "unknown")
            if pvid not in version_ids:
                versions.append(ModelVersion(id=pvid, model_id=pmid, version="unknown")); version_ids.add(pvid)
            parents.append(pvid); edge(vid, pvid, "FINE_TUNED_FROM")
        if dlines or parents:
            pid = stable_asset_id("training_run", model.identifier, vv)
            if pid not in prov_ids:
                provenance.append(TrainingProvenance(id=pid, model_version_id=vid, run_type="fine_tuning" if parents else "training", base_model_version_ids=parents, dataset_lineage=dlines)); prov_ids.add(pid)
            for dline in dlines: edge(pid, dline.dataset_id, "TRAINED_ON")
            edge(pid, vid, "PRODUCES")

        if model.deployed_to:
            app_id = applications.get(model.deployed_to) or asset("deployment", model.deployed_to, source="model deployment hint")
            did = stable_asset_id("deployment_context", model.deployed_to, vv)
            if did not in deployment_ids:
                deployments.append(DeploymentContext(id=did, application_id=app_id, model_version_id=vid, environment="unknown")); deployment_ids.add(did)
            edge(did, vid, "DEPLOYED_AS")

    if report.stack_snapshot:
        for node in report.stack_snapshot.nodes:
            k = str(node.kind).lower()
            if k in {"agent", "tool", "prompt", "api", "runtime", "deployment"}:
                asset(k, node.id, source="stack discovery", metadata=node.metadata)

    if report.runtime_trace:
        rid = stable_asset_id("runtime", report.runtime_trace.trace_mode, report.runtime_trace.captured_at.isoformat())
        if rid not in asset_ids:
            assets.append(AIAsset(id=rid, kind="runtime", name=report.runtime_trace.trace_mode, source="runtime trace", metadata={"command": report.runtime_trace.command, "observed_env": report.runtime_trace.observed_env, "imported_modules": report.runtime_trace.imported_modules})); asset_ids.add(rid)
        for model in report.models:
            if model.deployed_to:
                did = stable_asset_id("deployment_context", model.deployed_to, model.last_updated.isoformat() if model.last_updated else "unknown")
                if did in deployment_ids: edge(did, rid, "RUNS_ON")

    for item in report.evaluation_evidence:
        name = str(item.get("model") or item.get("model_id") or "unknown"); vv = str(item.get("version") or "unknown")
        mid = asset("model", name, source="evaluation evidence"); vid = stable_asset_id("model_version", name, vv)
        if vid not in version_ids:
            versions.append(ModelVersion(id=vid, model_id=mid, version=vv)); version_ids.add(vid)
        eid = str(item.get("id") or stable_asset_id("evaluation", name, str(item.get("suite") or "unknown")))
        if eid not in eval_ids:
            evaluations.append(EvaluationEvidence(id=eid, model_version_id=vid, suite=str(item.get("suite") or "unknown"), passed=bool(item.get("passed", False)), metrics={k: float(v) for k, v in (item.get("metrics") or {}).items() if isinstance(v, (int, float))}, dataset_id=item.get("dataset_id"))); eval_ids.add(eid)
        edge(eid, vid, "EVALUATED_BY")

    return AIBOMDocument(assets=assets, model_versions=versions, artifact_identities=artifacts, training_provenance=provenance, deployments=deployments, evaluations=evaluations, relationships=relationships, metadata={"source": "AI-BOM Inspector scan", "asset_count": len(assets), "relationship_count": len(relationships)})
