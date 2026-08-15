from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

from .integrity import compute_file_sha256
from .network import RetryConfig, request_with_retry
from .model_risk_db import (
    load_model_advisory_db,
    load_model_hash_db,
    load_threat_taxonomy_db,
    load_training_source_db,
)
from .pickle_inspector import PickleScanError, inspect_pickle_file
from .tensor_fuzz import SafetensorsDataError, SafetensorsHeaderError, inspect_weight_files
from .types import ModelInfo, ModelIssue, apply_license_category_model, categorize_license
from .parsers import ParserError, parse_models_file


STALE_DAYS = 270
_SAFE_TENSOR_EXTENSIONS = {".safetensors"}
_PICKLE_EXTENSIONS = {".pkl", ".pickle", ".pt", ".pth"}


def _cache_path(cache_dir: Path, identifier: str) -> Path:
    sanitized = identifier.replace("/", "__")
    return cache_dir / f"{sanitized}.json"


def _normalize_hash(value: str) -> str:
    return value.lower().replace("sha256:", "").strip()


def _is_valid_sha256(value: str) -> bool:
    if len(value) != 64:
        return False
    return all(char in "0123456789abcdef" for char in value)


def _threat_context_from_mapping(mapping: dict) -> str:
    if not mapping:
        return ""
    parts: list[str] = []
    threats = mapping.get("threats") or []
    stride = mapping.get("stride") or []
    atlas = mapping.get("mitre_atlas") or []
    if threats:
        parts.append(f"Threats: {', '.join(threats)}")
    if stride:
        parts.append(f"STRIDE: {', '.join(stride)}")
    if atlas:
        parts.append(f"MITRE ATLAS: {', '.join(atlas)}")
    return f" ({'; '.join(parts)})" if parts else ""


def _taxonomy_context(code: str) -> str:
    taxonomy = load_threat_taxonomy_db()
    mapping = (taxonomy.get("mappings") or {}).get(code, {})
    return _threat_context_from_mapping(mapping)


def _collect_declared_hashes(entry: dict) -> list[str]:
    hashes: list[str] = []
    raw = entry.get("hashes") or entry.get("fingerprints") or []
    if isinstance(raw, str):
        hashes.append(_normalize_hash(raw))
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, str):
                hashes.append(_normalize_hash(item))
            elif isinstance(item, dict):
                for value in item.values():
                    if isinstance(value, str):
                        hashes.append(_normalize_hash(value))
    if isinstance(entry.get("sha256"), str):
        hashes.append(_normalize_hash(entry["sha256"]))
    return [value for value in hashes if value]


def _coerce_artifacts(entry: dict) -> list[dict]:
    # Support multiple shapes: 'artifacts' list, single 'artifact' dict, or legacy top-level 'path'
    artifacts = entry.get("artifacts") or entry.get("artifact") or []
    if isinstance(artifacts, dict):
        artifacts = [artifacts]
    normalized: list[dict] = []
    if isinstance(artifacts, list):
        for item in artifacts:
            if isinstance(item, str):
                normalized.append({"path": item})
            elif isinstance(item, dict):
                normalized.append(dict(item))
    # Fallback: support legacy single 'path' key on the model entry
    if not normalized and isinstance(entry.get("path"), str):
        normalized.append({"path": entry.get("path")})
    return normalized


def _coerce_strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    if isinstance(value, dict):
        return [item for item in value.values() if isinstance(item, str)]
    return []


def _collect_training_sources(entry: dict) -> list[str]:
    sources: list[str] = []
    for key in ("training_sources", "training_source", "datasets", "data_sources", "training_data"):
        sources.extend(_coerce_strings(entry.get(key)))
    return sorted({source for source in sources if source})


def _collect_lineage(entry: dict) -> tuple[list[str], list[str]]:
    base_models: list[str] = []
    fine_tuned: list[str] = []
    for key in ("base_model", "base_models", "lineage", "derived_from", "parent_model"):
        base_models.extend(_coerce_strings(entry.get(key)))
    fine_tuned.extend(_coerce_strings(entry.get("fine_tuned_from")))
    for key in ("fine_tune_base", "fine_tuned_base"):
        fine_tuned.extend(_coerce_strings(entry.get(key)))
    return sorted({value for value in base_models if value}), sorted({value for value in fine_tuned if value})


def _detect_artifact_kind(path: Path, declared_kind: Optional[str]) -> str:
    if declared_kind:
        return declared_kind.lower()
    suffix = path.suffix.lower()
    if suffix in _SAFE_TENSOR_EXTENSIONS:
        return "safetensors"
    if suffix in _PICKLE_EXTENSIONS:
        return "pickle"
    return "unknown"


def _analyze_artifacts(
    artifacts: list[dict],
    declared_hashes: list[str],
) -> tuple[list[str], list[ModelIssue], list[ModelIssue]]:
    hashes: list[str] = []
    issues: list[ModelIssue] = []
    trust_signals: list[ModelIssue] = []

    for artifact in artifacts:
        path_text = artifact.get("path")
        if not path_text:
            continue
        path = Path(path_text)
        if not path.exists():
            issues.append(
                ModelIssue(
                    f"[MODEL_ARTIFACT_MISSING] Artifact not found: {path}",
                    severity="medium",
                    code="MODEL_ARTIFACT_MISSING",
                )
            )
            continue

        try:
            artifact_hash = compute_file_sha256(path)
            hashes.append(artifact_hash)
            if declared_hashes and artifact_hash not in declared_hashes:
                issues.append(
                    ModelIssue(
                        f"[MODEL_HASH_MISMATCH] {path} hash does not match declared fingerprints",
                        severity="high",
                        code="SUPPLY_CHAIN_ANOMALY",
                    )
                )
        except Exception as exc:
            issues.append(
                ModelIssue(
                    f"[MODEL_HASH_FAILED] Unable to hash {path}: {exc}",
                    severity="low",
                    code="MODEL_HASH_FAILED",
                )
            )

        kind = _detect_artifact_kind(path, artifact.get("kind") or artifact.get("type"))
        if kind == "safetensors":
            try:
                results = inspect_weight_files([path])
            except (SafetensorsHeaderError, SafetensorsDataError, OSError) as exc:
                issues.append(
                    ModelIssue(
                        f"[MODEL_WEIGHT_SCAN_FAILED] {path}: {exc}",
                        severity="medium",
                        code="MODEL_WEIGHT_SCAN_FAILED",
                    )
                )
                continue
            result = results[0]
            if result.suspected:
                issues.append(
                    ModelIssue(
                        f"[MODEL_WEIGHT_ANOMALY] {path} flagged for poisoned or steganographic tensors"
                        f"{_taxonomy_context('MODEL_WEIGHT_ANOMALY')}",
                        severity="high",
                        code="MODEL_WEIGHT_ANOMALY",
                    )
                )
            else:
                trust_signals.append(
                    ModelIssue(
                        f"[MODEL_WEIGHT_SCAN_OK] {path} passed tensor anomaly checks",
                        severity="low",
                        code="MODEL_WEIGHT_SCAN_OK",
                    )
                )
        elif kind == "pickle":
            try:
                result = inspect_pickle_file(path)
            except PickleScanError as exc:
                issues.append(
                    ModelIssue(
                        f"[MODEL_PICKLE_SCAN_FAILED] {path}: {exc}",
                        severity="medium",
                        code="MODEL_PICKLE_SCAN_FAILED",
                    )
                )
                continue
            if result.suspected:
                issues.append(
                    ModelIssue(
                        f"[PICKLE_DANGEROUS_GLOBALS] {path} references dangerous globals"
                        f"{_taxonomy_context('PICKLE_DANGEROUS_GLOBALS')}",
                        severity="high",
                        code="PICKLE_DANGEROUS_GLOBALS",
                    )
                )
            else:
                trust_signals.append(
                    ModelIssue(
                        f"[MODEL_PICKLE_SCAN_OK] {path} contains no dangerous globals",
                        severity="low",
                        code="MODEL_PICKLE_SCAN_OK",
                    )
                )
        elif kind != "unknown":
            trust_signals.append(
                ModelIssue(
                    f"[MODEL_ARTIFACT_DECLARED] {path} tracked as {kind}",
                    severity="low",
                    code="MODEL_ARTIFACT_DECLARED",
                )
            )

    if artifacts and not declared_hashes:
        issues.append(
            ModelIssue(
                "[MODEL_HASH_MISSING] No declared hashes for model artifacts",
                severity="medium",
                code="MODEL_HASH_MISSING",
            )
        )
    if declared_hashes and artifacts and not hashes:
        issues.append(
            ModelIssue(
                "[MODEL_HASH_UNVERIFIED] Declared hashes could not be verified against artifacts",
                severity="medium",
                code="SUPPLY_CHAIN_ANOMALY",
            )
        )

    return hashes, issues, trust_signals


def fetch_model_metadata(identifier: str, cache_dir: Path | None = None, offline: bool = False) -> dict:
    cache = cache_dir or Path(".aibom_cache")
    cache.mkdir(parents=True, exist_ok=True)
    cache_file = _cache_path(cache, identifier)
    if cache_file.exists():
        try:
            return json.loads(cache_file.read_text())
        except Exception:
            pass

    data: Dict[str, object] = {"id": identifier, "source": "huggingface"}

    if offline:
        data["offline"] = True
        cache_file.write_text(json.dumps(data))
        return data

    try:
        try:
            from huggingface_hub import HfApi

            api = HfApi()
            info = api.model_info(identifier)
            data["license"] = getattr(info, "license", None)
            if getattr(info, "lastModified", None):
                data["last_updated"] = info.lastModified.isoformat()
        except ImportError:
            import requests  # type: ignore[import-untyped]

            response = request_with_retry(
                "GET",
                f"https://huggingface.co/api/models/{identifier}",
                timeout=10,
                retry_config=RetryConfig(),
            )
            if response.status_code == 200:
                payload = response.json()
                data["license"] = payload.get("license")
                if payload.get("lastModified"):
                    data["last_updated"] = payload["lastModified"]
    except Exception as exc:
        data["error"] = f"metadata lookup failed: {exc}"

    cache_file.write_text(json.dumps(data))
    return data


def parse_model_entry(entry: dict) -> ModelInfo:
    identifier = entry.get("id") or entry.get("name") or "unknown-model"
    source = entry.get("source", "local")
    license_name: Optional[str] = entry.get("license")
    last_updated_raw: Optional[str] = entry.get("last_updated")
    last_updated = datetime.fromisoformat(last_updated_raw) if last_updated_raw else None

    issues: List[ModelIssue] = []
    trust_signals: List[ModelIssue] = []
    hashes: list[str] = _collect_declared_hashes(entry)
    invalid_hashes = [value for value in hashes if not _is_valid_sha256(value)]
    if invalid_hashes:
        issues.append(
            ModelIssue(
                f"[MODEL_HASH_INVALID] Invalid SHA256 hashes detected: {', '.join(invalid_hashes)}",
                severity="medium",
                code="MODEL_HASH_INVALID",
            )
        )
    hashes = [value for value in hashes if _is_valid_sha256(value)]
    training_sources = _collect_training_sources(entry)
    base_models, fine_tuned_from = _collect_lineage(entry)

    if entry.get("offline"):
        issues.append(
            ModelIssue(
                "[OFFLINE_MODE] Remote metadata lookup skipped",
                severity="low",
                code="OFFLINE_MODE",
            )
        )

    if entry.get("error"):
        issues.append(
            ModelIssue(
                f"[METADATA_UNAVAILABLE] {entry['error']}",
                severity="low",
                code="METADATA_UNAVAILABLE",
            )
        )

    if not license_name:
        issues.append(
            ModelIssue(
                "[UNKNOWN_LICENSE] Missing license information",
                severity="high",
                code="UNKNOWN_LICENSE",
            )
        )
    else:
        category = categorize_license(license_name)
        if category in {"copyleft", "weak_copyleft"}:
            issues.append(
                ModelIssue(
                    "[LICENSE_RISK] Copyleft/reciprocal terms may apply",
                    severity="medium",
                    code="LICENSE_RISK",
                )
            )
        elif category in {"restricted", "proprietary"}:
            issues.append(
                ModelIssue(
                    "[LICENSE_RESTRICTED] Custom or restricted model license detected",
                    severity="medium",
                    code="MODEL_LICENSE_RESTRICTED",
                )
            )
            if category == "proprietary":
                issues.append(
                    ModelIssue(
                        "[PROPRIETARY_AI_RISK] Proprietary model license may limit auditability or reuse",
                        severity="medium",
                        code="PROPRIETARY_AI_RISK",
                    )
                )
        elif category == "unknown":
            issues.append(
                ModelIssue(
                    "[UNKNOWN_LICENSE] License could not be classified",
                    severity="medium",
                    code="UNKNOWN_LICENSE",
                )
            )

    if last_updated and last_updated < datetime.utcnow() - timedelta(days=STALE_DAYS):
        issues.append(
            ModelIssue(
                "[STALE_MODEL] Model metadata is stale",
                severity="medium",
                code="STALE_MODEL",
            )
        )

    if source not in {"huggingface", "local", "private", "openai"}:
        issues.append(
            ModelIssue(
                f"[UNVERIFIED_SOURCE] Unrecognized source '{source}'",
                severity="medium",
                code="UNVERIFIED_SOURCE",
            )
        )

    artifact_hashes, artifact_issues, artifact_trust = _analyze_artifacts(
        _coerce_artifacts(entry),
        hashes,
    )
    hashes.extend(artifact_hashes)
    issues.extend(artifact_issues)
    trust_signals.extend(artifact_trust)

    issues.extend(_assess_training_sources(training_sources))

    model = ModelInfo(
        identifier=identifier,
        source=source,
        license=license_name,
        last_updated=last_updated,
        base_models=base_models,
        fine_tuned_from=fine_tuned_from,
        training_sources=training_sources,
        hashes=sorted({value for value in hashes if value}),
        artifacts=[artifact.get("path") for artifact in _coerce_artifacts(entry)],
        issues=issues,
        trust_signals=trust_signals,
    )
    apply_license_category_model(model)
    return model


def scan_models_from_file(path: Path, *, max_bytes: int | None = None) -> List[ModelInfo]:
    if not path or not path.exists():
        return []

    try:
        data = parse_models_file(path, max_bytes=max_bytes)
    except ParserError:
        return []
    entries = data.models

    models: List[ModelInfo] = []
    for entry in entries:
        # Support pydantic v2 (model_dump) and v1 (dict)
        if hasattr(entry, "model_dump"):
            entry_dict = entry.model_dump()
        elif hasattr(entry, "dict"):
            entry_dict = entry.dict()
        else:
            entry_dict = dict(entry)
        models.append(parse_model_entry(entry_dict))
    return models


def summarize_models(model_ids: List[str], offline: bool = False) -> List[ModelInfo]:
    models: List[ModelInfo] = []
    for identifier in model_ids:
        metadata = fetch_model_metadata(identifier, offline=offline)
        models.append(parse_model_entry(metadata))
    return models


def _apply_hash_reputation(models: List[ModelInfo], hash_db: dict) -> None:
    malicious = {
        _normalize_hash(entry.get("sha256", "")): entry
        for entry in (hash_db.get("malicious") or [])
        if isinstance(entry, dict)
    }
    trusted = {
        _normalize_hash(entry.get("sha256", "")): entry
        for entry in (hash_db.get("trusted") or [])
        if isinstance(entry, dict)
    }

    for model in models:
        for hash_value in model.hashes:
            malicious_entry = malicious.get(_normalize_hash(hash_value))
            if malicious_entry:
                context = _threat_context_from_mapping(malicious_entry)
                model.issues.append(
                    ModelIssue(
                        f"[MALICIOUS_MODEL_HASH] {hash_value} flagged as malicious"
                        f"{context or _taxonomy_context('MODEL_HASH_MALICIOUS')}",
                        severity=str(malicious_entry.get("severity", "high")),
                        code="MODEL_HASH_MALICIOUS",
                    )
                )
                continue
            trusted_entry = trusted.get(_normalize_hash(hash_value))
            if trusted_entry:
                source = trusted_entry.get("source", "trusted registry")
                model.trust_signals.append(
                    ModelIssue(
                        f"[KNOWN_GOOD_HASH] {hash_value} matches {source}",
                        severity="low",
                        code="MODEL_HASH_TRUSTED",
                    )
                )


def _apply_model_advisories(models: List[ModelInfo], advisory_db: dict) -> None:
    advisories = advisory_db.get("advisories") or []
    for entry in advisories:
        if not isinstance(entry, dict):
            continue
        model_ids = {str(entry.get("model_id", ""))}
        aliases = entry.get("aliases") or []
        if isinstance(aliases, list):
            model_ids.update({str(alias) for alias in aliases})
        hashes = {_normalize_hash(value) for value in (entry.get("hashes") or []) if isinstance(value, str)}
        advisory_list = entry.get("advisories") or []
        for model in models:
            if model.identifier not in model_ids and not hashes.intersection(model.hashes):
                continue
            for advisory in advisory_list:
                if not isinstance(advisory, dict):
                    continue
                advisory_id = advisory.get("id", "MODEL_VULNERABILITY")
                summary = advisory.get("summary", "Model advisory")
                context = _threat_context_from_mapping(advisory)
                metadata = {}
                if "exploit_maturity" in advisory:
                    metadata["exploit_maturity"] = advisory.get("exploit_maturity")
                if "active_exploitation" in advisory:
                    metadata["active_exploitation"] = advisory.get("active_exploitation")
                code_token = (
                    f"{advisory_id}|MODEL_VULNERABILITY"
                    if advisory_id
                    else "MODEL_VULNERABILITY"
                )
                model.issues.append(
                    ModelIssue(
                        f"[MODEL_VULNERABILITY] {advisory_id}: {summary}{context}",
                        severity=str(advisory.get("severity", "high")),
                        code=code_token,
                        metadata=metadata,
                    )
                )


def _assess_training_sources(sources: list[str]) -> list[ModelIssue]:
    if not sources:
        return []

    db = load_training_source_db()
    fingerprints = db.get("fingerprints") or []
    issues: list[ModelIssue] = []
    for source in sources:
        source_l = source.lower()
        for entry in fingerprints:
            if not isinstance(entry, dict):
                continue
            pattern = str(entry.get("pattern", "")).lower()
            if not pattern or pattern not in source_l:
                continue
            risk = str(entry.get("risk", "medium")).lower()
            severity = "high" if risk == "high" else "low" if risk == "low" else "medium"
            signal = str(entry.get("signal", "TRAINING_SOURCE_RISK")).upper()
            note = entry.get("note") or entry.get("description") or ""
            message = f"[{signal}] Training source '{source}' flagged"
            if note:
                message = f"{message}: {note}"
            issues.append(
                ModelIssue(
                    f"{message}{_taxonomy_context(signal)}",
                    severity=severity,
                    code=signal,
                )
            )
    return issues


def _apply_lineage_risks(models: List[ModelInfo]) -> None:
    index = {model.identifier: model for model in models}
    for model in models:
        lineage = sorted({*model.base_models, *model.fine_tuned_from})
        if not lineage:
            continue
        for base_id in lineage:
            base = index.get(base_id)
            if not base:
                model.issues.append(
                    ModelIssue(
                        f"[MODEL_LINEAGE_UNKNOWN] Base model '{base_id}' not found in scan context",
                        severity="medium",
                        code="MODEL_LINEAGE_UNKNOWN",
                    )
                )
                continue
            if base.license_category in {"unknown", "restricted", "proprietary"}:
                model.issues.append(
                    ModelIssue(
                        f"[MODEL_LINEAGE_RISK] Base model '{base_id}' has license risk ({base.license_category})",
                        severity="medium",
                        code="MODEL_LINEAGE_RISK",
                    )
                )
            high_issues = [issue for issue in base.issues if issue.severity == "high"]
            if high_issues:
                model.issues.append(
                    ModelIssue(
                        f"[FINE_TUNE_INHERITANCE_RISK] Base model '{base_id}' carries high-risk findings",
                        severity="high",
                        code="FINE_TUNE_INHERITANCE_RISK",
                    )
                )


def enrich_models_with_cves(models: List[ModelInfo]) -> List[ModelInfo]:
    """Cross-check model identifiers and hashes against advisory feeds."""

    _apply_model_advisories(models, load_model_advisory_db())
    _apply_hash_reputation(models, load_model_hash_db())
    _apply_lineage_risks(models)
    return models
