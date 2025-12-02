from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


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


def categorize_license(license_name: Optional[str]) -> str:
    if not license_name:
        return "unknown"

    normalized = license_name.lower()
    for token, category in LICENSE_CATEGORIES:
        if token in normalized:
            return category
    if "proprietary" in normalized or "custom" in normalized:
        return "proprietary"
    return "unknown"
