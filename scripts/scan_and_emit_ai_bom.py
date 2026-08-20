#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the AI-BOM Inspector scan and emit a structured AI-BOM alongside the report.")
    parser.add_argument("--requirements", required=True)
    parser.add_argument("--models-file", required=True)
    parser.add_argument("--policy")
    parser.add_argument("--output", default="report.json")
    parser.add_argument("--ai-bom-output", default="ai-bom.json")
    parser.add_argument("--format", default="json")
    parser.add_argument("--fail-on-score", type=int)
    parser.add_argument("--offline", action="store_true")
    args, passthrough = parser.parse_known_args()
    root = Path(__file__).resolve().parents[1]
    report_path = (root / args.output).resolve()
    ai_bom_path = (root / args.ai_bom_output).resolve()
    command = [sys.executable, "-m", "aibom_inspector.cli_shim", "scan", "--requirements", args.requirements, "--models-file", args.models_file, "--format", args.format, "--output", str(report_path)]
    if args.policy:
        command += ["--policy", args.policy]
    if args.fail_on_score is not None:
        command += ["--fail-on-score", str(args.fail_on_score)]
    if args.offline:
        command.append("--offline")
    command.extend(passthrough)
    scan_rc = subprocess.run(command, cwd=root).returncode
    if not report_path.exists():
        return scan_rc
    build = subprocess.run([sys.executable, str(root / "scripts" / "build_ai_bom.py"), str(report_path), "--output", str(ai_bom_path)], cwd=root)
    if build.returncode:
        return build.returncode
    payload = json.loads(ai_bom_path.read_text(encoding="utf-8"))
    print(f"AI-BOM emitted: {ai_bom_path} | assets={len(payload.get('assets', []))} | relationships={len(payload.get('relationships', []))}")
    return scan_rc


if __name__ == "__main__":
    raise SystemExit(main())
