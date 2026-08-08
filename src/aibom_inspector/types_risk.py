from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional

from .data_loader import load_json_data


@dataclass
class RiskSettings:
    """Tunable weights for the 0-100 AI stack risk score."""

    max_score: int = 100
    severity_penalties: dict[str, int] = field(default_factory=lambda: {"high": 8, "medium": 4, "low": 2})
    governance_penalty: int = 3
    cve_penalty: int = 7
    missing_intel_penalty: int = 2
    active_exploitation_penalty: int = 25
    scoring_model: str = "default"
    scoring_model_version: str = "v1"
    category_weights: dict[str, float] = field(default_factory=dict)
    weight_scale: float = 10.0
    org_weights: dict[str, int] = field(default_factory=dict)
    temporal_multipliers: dict[str, float] = field(
        default_factory=lambda: {"active_exploitation": 1.8, "mature": 1.4, "poc": 1.2}
    )
    asset_criticality_multipliers: dict[str, float] = field(
        default_factory=lambda: {"low": 1.0, "medium": 1.2, "high": 1.5, "critical": 2.0}
    )
    data_sensitivity_multipliers: dict[str, float] = field(
        default_factory=lambda: {"public": 1.0, "internal": 1.2, "confidential": 1.5, "restricted": 2.0}
    )
    environment_multipliers: dict[str, float] = field(
        default_factory=lambda: {"dev": 1.0, "test": 1.1, "staging": 1.3, "prod": 1.7}
    )

    @property
    def temporal_weights(self) -> dict[str, float]:
        """Backward-compatible alias for temporal multiplier settings."""

        return self.temporal_multipliers

    def penalty_for(self, severity: str) -> int:
        return self.severity_penalties.get(severity.lower(), 5)

    def as_dict(self) -> dict:
        return {
            "max_score": self.max_score,
            "severity_penalties": self.severity_penalties,
            "governance_penalty": self.governance_penalty,
            "cve_penalty": self.cve_penalty,
            "missing_intel_penalty": self.missing_intel_penalty,
            "active_exploitation_penalty": self.active_exploitation_penalty,
            "scoring_model": self.scoring_model,
            "scoring_model_version": self.scoring_model_version,
            "category_weights": self.category_weights,
            "weight_scale": self.weight_scale,
            "org_weights": self.org_weights,
            "temporal_multipliers": self.temporal_multipliers,
            "asset_criticality_multipliers": self.asset_criticality_multipliers,
            "data_sensitivity_multipliers": self.data_sensitivity_multipliers,
            "environment_multipliers": self.environment_multipliers,
        }


def temporal_penalty(
    metadata: dict[str, object],
    settings: dict[str, float] | RiskSettings,
    *,
    base_penalty: float = 0.0,
) -> float:
    """Return the additive temporal delta for legacy explanation callers.

    The main scorer stores temporal risk as a multiplier plus an optional active
    exploitation override. Older report-enrichment code expects the additional
    penalty to add on top of the severity baseline, so this helper returns only
    that delta while preserving the active-exploitation floor.
    """

    if not metadata:
        return 0.0
    if isinstance(settings, RiskSettings):
        weights = settings.temporal_multipliers
        active_exploitation_penalty = settings.active_exploitation_penalty
    else:
        weights = settings
        active_exploitation_penalty = RiskSettings().active_exploitation_penalty

    multiplied_penalty = base_penalty * temporal_multiplier(metadata, weights)
    override_penalty = temporal_override_penalty(
        metadata, active_exploitation_penalty=active_exploitation_penalty
    )
    effective_penalty = max(multiplied_penalty, override_penalty or 0.0)
    return max(0.0, effective_penalty - base_penalty)


def temporal_multiplier(metadata: dict[str, object], temporal_multipliers: dict[str, float]) -> float:
    if not metadata:
        return 1.0
    if metadata.get("active_exploitation") is True:
        return temporal_multipliers.get("active_exploitation", 1.0)
    maturity = str(metadata.get("exploit_maturity", "")).lower()
    if maturity in {"active", "mature", "high"}:
        return temporal_multipliers.get("mature", 1.0)
    if maturity in {"poc", "proof-of-concept", "medium"}:
        return temporal_multipliers.get("poc", 1.0)
    return 1.0


def temporal_override_penalty(
    metadata: dict[str, object], *, active_exploitation_penalty: int
) -> int | None:
    if not metadata:
        return None
    if metadata.get("active_exploitation") is True:
        return active_exploitation_penalty
    return None


LICENSE_CATEGORIES = [
    ("cc-by-sa", "copyleft"),
    ("cc-by-nd", "proprietary"),
    ("cc-by-nc", "proprietary"),
    ("cc-by", "permissive"),
    ("gpl", "copyleft"),
    ("agpl", "copyleft"),
    ("lgpl", "weak_copyleft"),
    ("mpl", "weak_copyleft"),
    ("apache", "permissive"),
    ("mit", "permissive"),
    ("bsd", "permissive"),
]


_LICENSE_DB_PATH: Path | None = None


def set_license_risk_db_path(path: Path | None) -> None:
    global _LICENSE_DB_PATH
    _LICENSE_DB_PATH = path
    _load_license_overrides.cache_clear()


@lru_cache(maxsize=None)
def _load_license_overrides() -> dict[str, dict[str, str]]:
    data = load_json_data("license_risk_db.json", _LICENSE_DB_PATH)
    aliases = {str(key).lower(): str(value) for key, value in (data.get("aliases") or {}).items()}
    tokens = {str(key).lower(): str(value) for key, value in (data.get("tokens") or {}).items()}
    return {"aliases": aliases, "tokens": tokens}


def categorize_license(license_name: Optional[str]) -> str:
    if not license_name:
        return "unknown"

    normalized = license_name.lower()
    overrides = _load_license_overrides()
    if normalized in overrides["aliases"]:
        return overrides["aliases"][normalized]
    for token, category in overrides["tokens"].items():
        if token and token in normalized:
            return category
    for token, category in LICENSE_CATEGORIES:
        if token in normalized:
            return category
    if "proprietary" in normalized or "custom" in normalized:
        return "proprietary"
    return "unknown"
