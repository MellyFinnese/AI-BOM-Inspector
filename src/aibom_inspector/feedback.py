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
