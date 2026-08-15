#!/usr/bin/env bash
set -euo pipefail

# Single-command demo: runs the scanner over the tiny vulnerable project and writes demo/report.json
# This demo is offline by default and shows policy enforcement for legacy .pkl artifacts.

echo "Running golden demo scan..."

# Run scanner with PYTHONPATH set so the local package is used.
# Clean demo-generated caches and outputs to ensure reproducibility from a fresh checkout
rm -rf demo/golden-vulnerable-ai/.aibom_cache demo/golden-vulnerable-ai/report.json || true

# Run scanner with PYTHONPATH set so the local package is used. Capture exit code but keep output file writing behavior.
set +e
PYTHONPATH=src python -m aibom_inspector.cli_shim scan --requirements demo/golden-vulnerable-ai/requirements.txt \
  --models-file demo/golden-vulnerable-ai/models.json \
  --policy demo/golden-vulnerable-ai/policy.yml \
  --format json --output demo/golden-vulnerable-ai/report.json --fail-on-score 70 --offline
SCAN_RC=$?
set -e

if [ "${SCAN_RC:-0}" -eq 0 ]; then
  echo "Scan completed; report at demo/golden-vulnerable-ai/report.json"
else
  echo "Scan exited with non-zero (policy failure or findings). Check demo/golden-vulnerable-ai/report.json for details."
fi

# Print a short human summary when available
if [ -f demo/golden-vulnerable-ai/report.json ]; then
  # If an applications mapping exists, merge it into the generated report so impact/owner mapping works
  if [ -f demo/golden-vulnerable-ai/applications.json ]; then
    tmpfile=$(mktemp)
    # Some jq builds do not support --argfile. Use -s to slurp two files and merge.
    jq -s '.[0] + {applications: (.[1])}' demo/golden-vulnerable-ai/report.json demo/golden-vulnerable-ai/applications.json > "$tmpfile" && mv "$tmpfile" demo/golden-vulnerable-ai/report.json || true
  fi
  jq '.summary // "N/A", .policy_action // "N/A", (.findings[]?.id // "")' demo/golden-vulnerable-ai/report.json || true
fi
