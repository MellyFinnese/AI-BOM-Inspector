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
    scoring_model: str = "default"
    scoring_model_version: str = "v1"
    category_weights: dict[str, float] = field(default_factory=dict)
    weight_scale: float = 10.0
    org_weights: dict[str, int] = field(default_factory=dict)
    temporal_weights: dict[str, int] = field(
        default_factory=lambda: {"active_exploitation": 6, "mature": 4, "poc": 2}
    )

    def penalty_for(self, severity: str) -> int:
        return self.severity_penalties.get(severity.lower(), 5)

    def as_dict(self) -> dict:
        return {
            "max_score": self.max_score,
            "severity_penalties": self.severity_penalties,
            "governance_penalty": self.governance_penalty,
            "cve_penalty": self.cve_penalty,
            "missing_intel_penalty": self.missing_intel_penalty,
            "scoring_model": self.scoring_model,
            "scoring_model_version": self.scoring_model_version,
            "category_weights": self.category_weights,
            "weight_scale": self.weight_scale,
            "org_weights": self.org_weights,
            "temporal_weights": self.temporal_weights,
        }


def temporal_penalty(metadata: dict[str, object], temporal_weights: dict[str, int]) -> int:
    if not metadata:
        return 0
    if metadata.get("active_exploitation") is True:
        return temporal_weights.get("active_exploitation", 0)
    maturity = str(metadata.get("exploit_maturity", "")).lower()
    if maturity in {"active", "mature", "high"}:
        return temporal_weights.get("mature", 0)
    if maturity in {"poc", "proof-of-concept", "medium"}:
        return temporal_weights.get("poc", 0)
    return 0


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
