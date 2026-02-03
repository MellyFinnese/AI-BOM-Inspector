from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class FeedbackEntry:
    summary: str
    category: str
    priority: str
    finding_code: str | None = None
    organization: str | None = None
    contact: str | None = None
    workflow_stage: str | None = None
    notes: str | None = None
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def as_dict(self) -> dict:
        return asdict(self)


def load_feedback(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return json.loads(path.read_text())


def append_feedback(path: Path, entry: FeedbackEntry) -> None:
    items = load_feedback(path)
    items.append(entry.as_dict())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(items, indent=2))


def summarize_feedback(entries: list[dict]) -> dict:
    categories: dict[str, int] = {}
    priorities: dict[str, int] = {}
    workflow_stages: dict[str, int] = {}
    organizations: dict[str, int] = {}

    for entry in entries:
        category = entry.get("category") or "unknown"
        priority = entry.get("priority") or "unknown"
        workflow = entry.get("workflow_stage") or "unspecified"
        org = entry.get("organization") or "unspecified"
        categories[category] = categories.get(category, 0) + 1
        priorities[priority] = priorities.get(priority, 0) + 1
        workflow_stages[workflow] = workflow_stages.get(workflow, 0) + 1
        organizations[org] = organizations.get(org, 0) + 1

    return {
        "total": len(entries),
        "by_category": dict(sorted(categories.items())),
        "by_priority": dict(sorted(priorities.items())),
        "by_workflow_stage": dict(sorted(workflow_stages.items())),
        "by_organization": dict(sorted(organizations.items())),
    }
