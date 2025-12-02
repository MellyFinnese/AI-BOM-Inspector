from __future__ import annotations

"""Shared data structures for dependency and model inspection.

This module re-exports the primary dataclasses that were previously defined
in a single file. The definitions now live in domain-focused modules to make
it easier to evolve each area independently while keeping the public import
paths stable.
"""

from .types_dependencies import DependencyInfo, DependencyIssue, apply_license_category_dependency
from .types_models import ModelInfo, ModelIssue, apply_license_category_model
from .types_report import Report
from .types_risk import LICENSE_CATEGORIES, RiskSettings, categorize_license

__all__ = [
    "DependencyInfo",
    "DependencyIssue",
    "ModelInfo",
    "ModelIssue",
    "Report",
    "RiskSettings",
    "LICENSE_CATEGORIES",
    "apply_license_category_dependency",
    "apply_license_category_model",
    "categorize_license",
]
