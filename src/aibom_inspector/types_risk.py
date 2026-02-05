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

    def penalty_for(self, severity: str) -> int:
        return self.severity_penalties.get(severity.lower(), 5)

    def as_dict(self) -> dict:
        return {
            "max_score": self.max_score,
            "severity_penalties": self.severity_penalties,
            "governance_penalty": self.governance_penalty,
            "cve_penalty": self.cve_penalty,
        }


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
