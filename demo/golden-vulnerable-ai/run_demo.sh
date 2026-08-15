#!/usr/bin/env bash
set -euo pipefail

# Single-command demo: runs the scanner over the tiny vulnerable project and writes demo/report.json
# This demo is offline by default and shows policy enforcement for legacy .pkl artifacts.

echo "Running golden demo scan..."

# Run scanner with PYTHONPATH set so the local package is used.
PYTHONPATH=src python -m aibom_inspector.cli_shim scan --requirements demo/golden-vulnerable-ai/requirements.txt \
  --models-file demo/golden-vulnerable-ai/models.json \
  --policy demo/golden-vulnerable-ai/policy.yml \
  --format json --output demo/golden-vulnerable-ai/report.json --fail-on-score 70 --offline || SCAN_RC=$?

if [ "${SCAN_RC:-0}" -eq 0 ]; then
  echo "Scan completed; report at demo/golden-vulnerable-ai/report.json"
else
  echo "Scan exited with non-zero (policy failure or findings). Check demo/golden-vulnerable-ai/report.json for details."
fi

# Print a short human summary when available
if [ -f demo/golden-vulnerable-ai/report.json ]; then
  jq '.summary, .policy_action, .findings[]?.id' demo/golden-vulnerable-ai/report.json || true
fi
