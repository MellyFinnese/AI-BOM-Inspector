#!/usr/bin/env python3
"""Run a read-only Pickle VM tracer inside a constrained Docker container.

This runner builds a small image that contains the repository and then
runs a short python command inside the container that imports the
repo's pickle emulator (aibom_inspector.pickle_vm) and prints a JSON
trace to stdout. The container is run with strict constraints (no network,
read-only filesystem, dropped capabilities) to reduce risk.

Note: This script requires Docker to be available on the host. It will
fail cleanly with an explanatory error if Docker is not present.
"""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

IMAGE_TAG = "aibom-pickle-sandbox:local"
DOCKERFILE = "scripts/sandbox/Dockerfile.pickle-sandbox"


def docker_available() -> bool:
    return shutil.which("docker") is not None


def build_image(context_dir: Path) -> None:
    print("Building sandbox image (this may take a moment)...")
    subprocess.check_call([
        "docker",
        "build",
        "-t",
        IMAGE_TAG,
        "-f",
        str(context_dir / DOCKERFILE),
        str(context_dir),
    ])


def run_sandbox(target_file: Path, output_json: Path, timeout: int = 30) -> int:
    # Build the inline python command to run inside the container
    cmd = (
        "import sys, json, pathlib; sys.path.insert(0, '/app/src'); "
        "from aibom_inspector.pickle_vm import emulate_pickle_file; "
        "t=emulate_pickle_file(pathlib.Path(\"/workspace/target\")); print(json.dumps(t.as_dict()))"
    )

    docker_cmd = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--pids-limit",
        "100",
        "--cap-drop",
        "ALL",
        "--read-only",
        "-v",
        f"{str(target_file)}:/workspace/target:ro",
        "-v",
        f"{str(Path.cwd())}:/app:ro",
        IMAGE_TAG,
        cmd,
    ]

    print("Running sandboxed tracer...")
    proc = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        print("Sandbox runner failed:", proc.stderr, file=sys.stderr)
        return proc.returncode

    # write output
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(proc.stdout)
    print(f"Trace written to {output_json}")
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=Path, help="Path to the pickle file to analyze")
    parser.add_argument("--output", type=Path, default=Path("scripts/pickle_sandbox_output.json"))
    parser.add_argument("--no-build", action="store_true", help="Skip rebuilding the sandbox image")
    args = parser.parse_args()

    if not docker_available():
        print("Docker is not available on this host. Sandbox runner requires Docker.", file=sys.stderr)
        sys.exit(2)

    cwd = Path.cwd()

    if not args.no_build:
        try:
            build_image(cwd)
        except subprocess.CalledProcessError as exc:
            print("Failed to build sandbox image:", exc, file=sys.stderr)
            sys.exit(3)

    rc = run_sandbox(args.file, args.output)
    sys.exit(rc)


if __name__ == "__main__":
    main()
