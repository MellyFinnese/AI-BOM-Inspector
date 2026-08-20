#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from aibom_inspector.ai_bom_builder import build_ai_bom
from aibom_inspector.report_loader import load_report_payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a structured AI-BOM asset graph from a scan report")
    parser.add_argument("report", type=Path, help="Existing AI-BOM Inspector JSON report")
    parser.add_argument("--output", type=Path, default=Path("ai-bom.json"))
    args = parser.parse_args()
    report = load_report_payload(json.loads(args.report.read_text(encoding="utf-8")))
    document = build_ai_bom(report)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(document.model_dump_json(indent=2), encoding="utf-8")
    print(f"Wrote structured AI-BOM: {args.output}")
    print(f"Assets: {len(document.assets)} | Model versions: {len(document.model_versions)} | Relationships: {len(document.relationships)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
