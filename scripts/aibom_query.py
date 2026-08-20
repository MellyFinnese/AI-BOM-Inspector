#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from aibom_inspector.ai_assets import AIBOMDocument
from aibom_inspector.ai_bom_reasoning import attack_paths, blast_radius, diff_ai_bom, lineage


def load(path: Path) -> AIBOMDocument:
    return AIBOMDocument.model_validate_json(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Query an AI-BOM for lineage, impact, attack paths, or changes")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (("lineage", "show upstream lineage"), ("blast-radius", "show downstream impact")):
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("document", type=Path)
        cmd.add_argument("asset_id")
        cmd.add_argument("--max-depth", type=int, default=32)

    attack = sub.add_parser("attack-path", help="enumerate relationship paths to target assets")
    attack.add_argument("document", type=Path)
    attack.add_argument("start_id")
    attack.add_argument("targets", nargs="+")
    attack.add_argument("--max-depth", type=int, default=12)

    diff = sub.add_parser("diff", help="compare two AI-BOM snapshots")
    diff.add_argument("previous", type=Path)
    diff.add_argument("current", type=Path)

    args = parser.parse_args()
    if args.command == "diff":
        result = diff_ai_bom(load(args.previous), load(args.current)).to_dict()
    elif args.command == "lineage":
        result = {"asset_id": args.asset_id, "lineage": sorted(lineage(load(args.document), args.asset_id, max_depth=args.max_depth))}
    elif args.command == "blast-radius":
        result = {"asset_id": args.asset_id, "affected": sorted(blast_radius(load(args.document), args.asset_id, max_depth=args.max_depth))}
    else:
        result = {"start_id": args.start_id, "paths": attack_paths(load(args.document), args.start_id, args.targets, max_depth=args.max_depth)}

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
