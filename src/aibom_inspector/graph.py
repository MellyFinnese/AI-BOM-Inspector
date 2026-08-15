from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


def _parse_date(s: Optional[str]):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).date()
    except Exception:
        try:
            return datetime.fromisoformat(s).date()
        except Exception:
            return None


def _extract_issue_messages(dep: Dict[str, Any]) -> List[str]:
    msgs: List[str] = []
    for field in ("issue_details", "issues", "vulnerabilities", "vulns"):
        for entry in dep.get(field, []) or []:
            if isinstance(entry, str):
                msgs.append(entry)
            elif isinstance(entry, dict):
                msg = entry.get("message") or entry.get("description") or entry.get("code")
                if msg:
                    msgs.append(str(msg))
    return msgs


def _dep_has_cve(dep: Dict[str, Any], cve_id: str) -> bool:
    cve_id_up = cve_id.upper()
    # Check common fields
    for key in ("name", "id"):
        v = dep.get(key)
        if isinstance(v, str) and cve_id_up in v.upper():
            return True
    # Inspect issues/vuln messages
    for msg in _extract_issue_messages(dep):
        if cve_id_up in msg.upper():
            return True
    # Also check nested vulnerability objects
    for vuln in dep.get("vulnerabilities", []) or []:
        if isinstance(vuln, dict):
            if cve_id_up in str(vuln.get("id") or "").upper() or cve_id_up in str(vuln.get("name") or "").upper():
                return True
    return False


def _normalize_dep_name(name: str) -> str:
    # normalize "node_modules/lodash" -> "lodash"
    if not name:
        return ""
    return name.lower().split("/")[-1]


def _model_dep_entries(model: Dict[str, Any]) -> List[Any]:
    # model may list supporting dependencies in several shapes
    for key in ("supporting_dependencies", "dependencies", "observed_dependencies", "supporting"):
        val = model.get(key)
        if val:
            return val
    return []


def impact(report_path: str, cve_id: str) -> int:
    """Load a JSON report and compute blast radius for the given CVE.

    Prints a human-readable summary to stdout and returns 0 on success.
    """
    path = Path(report_path)
    if not path.exists():
        print(f"Report not found: {report_path}")
        return 1

    try:
        payload = json.loads(path.read_text())
    except Exception as exc:
        print(f"Failed to load report JSON: {exc}")
        return 1

    cve = cve_id.strip()

    deps = payload.get("dependencies", []) or []
    vuln_dep_names: Set[str] = set()
    for dep in deps:
        if _dep_has_cve(dep, cve):
            name = dep.get("name") or dep.get("id") or "unknown"
            vuln_dep_names.add(name)

    if not vuln_dep_names:
        print(f"VULNERABILITY: {cve}")
        print("No components in the report reference this CVE.")
        return 0

    # find affected models
    models = payload.get("models", []) or []
    affected_models: Set[str] = set()
    model_to_evidence: Dict[str, List[str]] = {}
    now = datetime.utcnow().date()

    for model in models:
        mid = model.get("id") or model.get("identifier") or model.get("name") or "unknown"
        deps_entries = _model_dep_entries(model)
        matched = False
        evidence: List[str] = []
        for entry in deps_entries:
            # entry can be a string or a dict
            if isinstance(entry, str):
                if any(_normalize_dep_name(entry) == _normalize_dep_name(d) for d in vuln_dep_names):
                    matched = True
                    evidence.append(str(entry))
            elif isinstance(entry, dict):
                name = entry.get("name") or entry.get("package") or entry.get("id")
                if name and any(_normalize_dep_name(name) == _normalize_dep_name(d) for d in vuln_dep_names):
                    # temporal filtering
                    start = _parse_date(entry.get("start_date") or entry.get("start"))
                    end = _parse_date(entry.get("end_date") or entry.get("end"))
                    include = True
                    if start and now < start:
                        include = False
                    if end and now > end:
                        include = False
                    if include:
                        matched = True
                        evidence.append(f"{name} (active {start or '...'} - {end or '...'})")
            # Also check model-level metadata like "observed_dependencies" strings
        if not deps_entries:
            # fallback: look for any mention within model issues/messages
            for issue in model.get("issues", []) or []:
                text = issue if isinstance(issue, str) else str(issue.get("message") or issue.get("code") or "")
                if cve.upper() in text.upper():
                    matched = True
                    evidence.append(f"model_issue:{text}")
        if matched:
            affected_models.add(mid)
            model_to_evidence[mid] = evidence or [", ".join(map(str, deps_entries))]

    # find applications and owners
    apps = payload.get("applications", []) or []
    app_lookup: Dict[str, Dict[str, Any]] = {app.get("name"): app for app in apps if app.get("name")}
    affected_apps: Set[str] = set()
    affected_owners: Set[str] = set()

    for model_name in affected_models:
        # find model entry again
        m = next((m for m in models if (m.get("id") or m.get("identifier") or m.get("name")) == model_name), None)
        if not m:
            continue
        deployed = m.get("deployed_to") or m.get("deployed") or m.get("deployedAs")
        if deployed:
            affected_apps.add(deployed)
            app = app_lookup.get(deployed)
            if app:
                owner = app.get("owner")
                if isinstance(owner, dict):
                    affected_owners.add(owner.get("name") or str(owner))
                elif isinstance(owner, str):
                    affected_owners.add(owner)

    # Print summary
    print(f"VULNERABILITY: {cve}")
    print("BLAST RADIUS:")
    print(f"  Models: {len(affected_models)}")
    print(f"  Applications: {len(affected_apps)}")
    print(f"  Owners: {len(affected_owners)}")
    print("")

    if affected_models:
        print("AFFECTED MODELS:")
        for m in sorted(affected_models):
            print(f"  - {m}")
        print("")

    if affected_apps:
        print("AFFECTED APPLICATIONS:")
        for a in sorted(affected_apps):
            print(f"  - {a}")
        print("")

    # Evidence sample
    print("EVIDENCE (sample):")
    shown = 0
    for m, ev in model_to_evidence.items():
        if shown >= 5:
            break
        print(f"  {m} -> {', '.join(ev)}")
        shown += 1

    return 0
