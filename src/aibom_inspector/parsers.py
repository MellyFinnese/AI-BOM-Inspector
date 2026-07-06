from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, List, Mapping

try:  # Optional dependency for YAML policy files
    import yaml
except Exception:  # pragma: no cover - exercised when PyYAML is missing
    yaml = None

from pydantic import BaseModel, ConfigDict, Field, ValidationError


SAFE_MAX_BYTES = 5_000_000


class ParserError(ValueError):
    pass


class PolicyExceptionSchema(BaseModel):
    code: str
    subject: str
    reason: str | None = None
    approved_by: str | None = None
    expires: str | None = None

    model_config = ConfigDict(extra="forbid", strict=True)


class PolicySchema(BaseModel):
    min_score: int | None = None
    max_cves: int | None = None
    disallow: List[str] = Field(default_factory=list)
    blocklist: List[str] = Field(default_factory=list)
    min_trust_score: int | None = None
    publisher_expectations: Mapping[str, str] = Field(default_factory=dict)
    trusted_registries: List[str] = Field(default_factory=list)
    protected_namespaces: List[str] = Field(default_factory=list)
    require_dependency_signatures: bool = False
    required_approvals: List[str] = Field(default_factory=list)
    lockfile_checksums: Mapping[str, str] = Field(default_factory=dict)
    require_lockfile_checksums: bool = False
    config_checksums: Mapping[str, str] = Field(default_factory=dict)
    ruleset_checksums: Mapping[str, str] = Field(default_factory=dict)
    plugin_signatures: Mapping[str, str] = Field(default_factory=dict)
    exceptions: List[PolicyExceptionSchema] = Field(default_factory=list)
    enforce_graph_policies: bool = False
    scoring_model: str | None = None
    scoring_model_version: str | None = None
    category_weights: Mapping[str, float] = Field(default_factory=dict)
    weight_scale: float | None = None
    org_weights: Mapping[str, int] = Field(default_factory=dict)
    temporal_multipliers: Mapping[str, float] = Field(default_factory=dict)
    asset_criticality_multipliers: Mapping[str, float] = Field(default_factory=dict)
    data_sensitivity_multipliers: Mapping[str, float] = Field(default_factory=dict)
    environment_multipliers: Mapping[str, float] = Field(default_factory=dict)
    missing_intel_penalty: int | None = None
    active_exploitation_penalty: int | None = None
    policy_version: str | None = None
    change_log: List[Mapping[str, Any]] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid", strict=True)


class RuntimeTraceSchema(BaseModel):
    trace_mode: str
    captured_at: str
    command: List[str] = Field(default_factory=list)
    imported_modules: List[str] = Field(default_factory=list)
    observed_models: List[str] = Field(default_factory=list)
    observed_ai_calls: List[Mapping[str, str]] = Field(default_factory=list)
    observed_dependencies: List[str] = Field(default_factory=list)
    observed_env: List[str] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid", strict=True)


class ModelArtifactSchema(BaseModel):
    path: str
    sha256: str | None = None
    size: int | None = None

    model_config = ConfigDict(extra="forbid", strict=True)


class ModelEntrySchema(BaseModel):
    id: str | None = None
    name: str | None = None
    source: str | None = None
    license: str | None = None
    last_updated: str | None = None
    base_models: List[str] = Field(default_factory=list)
    fine_tuned_from: List[str] = Field(default_factory=list)
    training_sources: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)
    artifacts: List[ModelArtifactSchema] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid", strict=True)


class ModelFileSchema(BaseModel):
    models: List[ModelEntrySchema] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid", strict=True)


class CycloneDXLicenseSchema(BaseModel):
    license: Mapping[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid", strict=True)


class CycloneDXComponentSchema(BaseModel):
    name: str
    version: str | None = None
    licenses: List[CycloneDXLicenseSchema] = Field(default_factory=list)
    properties: List[Mapping[str, Any]] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow", strict=True)


class CycloneDXSchema(BaseModel):
    bomFormat: str
    components: List[CycloneDXComponentSchema] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow", strict=True)


class SpdxPackageSchema(BaseModel):
    name: str
    versionInfo: str | None = None
    licenseDeclared: str | None = None
    licenseConcluded: str | None = None

    model_config = ConfigDict(extra="allow", strict=True)


class SpdxSchema(BaseModel):
    spdxVersion: str
    packages: List[SpdxPackageSchema] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow", strict=True)


@dataclass(frozen=True)
class SbomPayload:
    kind: str
    payload: CycloneDXSchema | SpdxSchema


class IssueSchema(BaseModel):
    message: str | None = None
    severity: str | None = None
    code: str | None = None
    metadata: Mapping[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="allow", strict=True)


class DependencyPayloadSchema(BaseModel):
    name: str
    version: str | None = None
    source: str | None = None
    license: str | None = None
    license_category: str | None = None
    registry: str | None = None
    signature_verified: bool | None = None
    issues: List[IssueSchema | str] = Field(default_factory=list)
    issue_details: List[IssueSchema | str] = Field(default_factory=list)
    trust_signals: List[IssueSchema | str] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow", strict=True)


class ModelPayloadSchema(BaseModel):
    id: str | None = None
    identifier: str | None = None
    source: str | None = None
    license: str | None = None
    license_category: str | None = None
    last_updated: str | None = None
    base_models: List[str] = Field(default_factory=list)
    fine_tuned_from: List[str] = Field(default_factory=list)
    training_sources: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)
    issues: List[IssueSchema | str] = Field(default_factory=list)
    issue_details: List[IssueSchema | str] = Field(default_factory=list)
    trust_signals: List[IssueSchema | str] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow", strict=True)


class RiskSettingsSchema(BaseModel):
    max_score: int | None = None
    severity_penalties: Mapping[str, int] = Field(default_factory=dict)
    governance_penalty: int | None = None
    cve_penalty: int | None = None
    scoring_model: str | None = None
    scoring_model_version: str | None = None
    category_weights: Mapping[str, float] = Field(default_factory=dict)
    weight_scale: float | None = None
    org_weights: Mapping[str, int] = Field(default_factory=dict)
    temporal_multipliers: Mapping[str, float] = Field(default_factory=dict)
    asset_criticality_multipliers: Mapping[str, float] = Field(default_factory=dict)
    data_sensitivity_multipliers: Mapping[str, float] = Field(default_factory=dict)
    environment_multipliers: Mapping[str, float] = Field(default_factory=dict)
    missing_intel_penalty: int | None = None

    model_config = ConfigDict(extra="allow", strict=True)


class ReportPayloadSchema(BaseModel):
    dependencies: List[DependencyPayloadSchema] = Field(default_factory=list)
    models: List[ModelPayloadSchema] = Field(default_factory=list)
    generated_at: str | None = None
    ai_summary: str | None = None
    risk_settings: RiskSettingsSchema | None = None
    provenance: Mapping[str, Any] | None = None
    approvals: List[str] = Field(default_factory=list)
    policy_metadata: Mapping[str, Any] | None = None
    intel_versions: Mapping[str, Any] | None = None
    score_explanation: Mapping[str, Any] | None = None

    model_config = ConfigDict(extra="allow", strict=True)


def read_text(path: Path, max_bytes: int | None = None) -> str:
    raw = path.read_bytes()
    if max_bytes is not None and len(raw) > max_bytes:
        raise ParserError(f"{path} exceeds safe size limit of {max_bytes} bytes")
    return raw.decode("utf-8", errors="replace")


def load_json_payload(path: Path, max_bytes: int | None = None) -> Any:
    try:
        return json.loads(read_text(path, max_bytes=max_bytes))
    except json.JSONDecodeError as exc:
        raise ParserError(f"Invalid JSON in {path}: {exc}") from exc


def load_yaml_payload(path: Path, max_bytes: int | None = None) -> Any:
    if yaml is None:
        raise ParserError("PyYAML is required to load YAML files.")
    try:
        return yaml.safe_load(read_text(path, max_bytes=max_bytes)) or {}
    except Exception as exc:
        raise ParserError(f"Invalid YAML in {path}: {exc}") from exc


def parse_policy_file(path: Path, max_bytes: int | None = None) -> PolicySchema:
    payload = load_yaml_payload(path, max_bytes=max_bytes)
    return PolicySchema.model_validate(payload)


def parse_runtime_trace_file(path: Path, max_bytes: int | None = None) -> RuntimeTraceSchema:
    payload = load_json_payload(path, max_bytes=max_bytes)
    return RuntimeTraceSchema.model_validate(payload)


def parse_models_file(path: Path, max_bytes: int | None = None) -> ModelFileSchema:
    payload = load_json_payload(path, max_bytes=max_bytes)
    if isinstance(payload, list):
        payload = {"models": payload}
    return ModelFileSchema.model_validate(payload)


def parse_sbom_file(path: Path, max_bytes: int | None = None) -> SbomPayload:
    payload = load_json_payload(path, max_bytes=max_bytes)
    if isinstance(payload, dict) and str(payload.get("bomFormat", "")).lower() == "cyclonedx":
        return SbomPayload(kind="cyclonedx", payload=CycloneDXSchema.model_validate(payload))
    if isinstance(payload, dict) and payload.get("spdxVersion"):
        return SbomPayload(kind="spdx", payload=SpdxSchema.model_validate(payload))
    raise ParserError("Unsupported SBOM payload")


def validate_or_none(schema: type[BaseModel], payload: Any) -> BaseModel | None:
    try:
        return schema.model_validate(payload)
    except ValidationError:
        return None


def serialize_validation_errors(errors: Iterable[Any]) -> List[str]:
    details = []
    for error in errors:
        message = error.get("msg", "validation error")
        location = ".".join(str(entry) for entry in error.get("loc", []))
        details.append(f"{location}: {message}" if location else message)
    return details
