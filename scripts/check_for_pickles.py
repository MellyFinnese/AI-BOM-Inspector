#!/usr/bin/env python3
import subprocess
import sys

# Get list of changed files between PR branch and main
try:
    subprocess.check_call(["git", "fetch", "origin", "main"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
except subprocess.CalledProcessError:
    pass
try:
    diff_out = subprocess.check_output(["git", "diff", "--name-only", "origin/main...HEAD"]).decode().splitlines()
except subprocess.CalledProcessError:
    diff_out = []

prohibited_exts = {".pkl", ".pt"}
violations = []
for f in diff_out:
    low = f.lower()
    for ext in prohibited_exts:
        if low.endswith(ext):
            violations.append(f)

if violations:
    print("Detected legacy model artifacts in PR:\n" + "\n".join(violations))
    print("Blocking merge: legacy Pickle formats are disallowed. Use Safetensors or GGUF instead.")
    sys.exit(1)

print("No legacy pickle artifacts detected in PR.")
sys.exit(0)
