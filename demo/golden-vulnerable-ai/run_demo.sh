#!/usr/bin/env bash
set -euo pipefail

# Single-command demo: runs the scanner over the tiny vulnerable project and writes demo/report.json
# This demo is offline by default and shows policy enforcement for legacy .pkl artifacts.

SCANNER_CMD="aibom scan --requirements demo/golden-vulnerable-ai/requirements.txt \
  --models-file demo/golden-vulnerable-ai/models.json \
  --format json --output demo/golden-vulnerable-ai/report.json --fail-on-score 70"

echo "Running golden demo scan..."
# Allow the scanner to fail (policy block) but still produce the report
if ${SCANNER_CMD}; then
  echo "Scan completed; report at demo/golden-vulnerable-ai/report.json"
else
  echo "Scan exited with non-zero (policy failure or findings). Check demo/golden-vulnerable-ai/report.json for details."
fi

# Print a short human summary when available
if [ -f demo/golden-vulnerable-ai/report.json ]; then
  jq '.summary, .policy_action, .findings[]?.id' demo/golden-vulnerable-ai/report.json || true
fi
