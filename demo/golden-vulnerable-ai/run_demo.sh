#!/usr/bin/env bash
set -euo pipefail

# Golden demo: one command produces a policy-enforced report and a structured AI-BOM.
# The demo remains offline-first and intentionally contains a legacy .pkl artifact.

echo "Running golden AI-BOM demo..."

rm -rf demo/golden-vulnerable-ai/.aibom_cache \
  demo/golden-vulnerable-ai/report.json \
  demo/golden-vulnerable-ai/ai-bom.json || true

set +e
PYTHONPATH=src python scripts/scan_and_emit_ai_bom.py \
  --requirements demo/golden-vulnerable-ai/requirements.txt \
  --models-file demo/golden-vulnerable-ai/models.json \
  --policy demo/golden-vulnerable-ai/policy.yml \
  --output demo/golden-vulnerable-ai/report.json \
  --ai-bom-output demo/golden-vulnerable-ai/ai-bom.json \
  --format json --fail-on-score 70 --offline
SCAN_RC=$?
set -e

# Merge deployment/application ownership context, then rebuild the AI-BOM so the
# final graph contains the complete demo context.
if [ -f demo/golden-vulnerable-ai/report.json ] && [ -f demo/golden-vulnerable-ai/applications.json ]; then
  tmpfile=$(mktemp)
  jq -s '.[0] + {applications: (.[1])}' \
    demo/golden-vulnerable-ai/report.json \
    demo/golden-vulnerable-ai/applications.json > "$tmpfile"
  mv "$tmpfile" demo/golden-vulnerable-ai/report.json
  PYTHONPATH=src python scripts/build_ai_bom.py \
    demo/golden-vulnerable-ai/report.json \
    --output demo/golden-vulnerable-ai/ai-bom.json
fi

if [ -f demo/golden-vulnerable-ai/report.json ]; then
  echo
  echo "=== SECURITY DECISION ==="
  jq '{policy_action: (.policy_action // "N/A"), score: (.score // "N/A"), finding_ids: [.findings[]?.id]}' \
    demo/golden-vulnerable-ai/report.json || true
fi

if [ -f demo/golden-vulnerable-ai/ai-bom.json ]; then
  echo
  echo "=== AI-BOM GRAPH ==="
  jq '{assets: (.assets | length), model_versions: (.model_versions | length), artifacts: (.artifact_identities | length), training_provenance: (.training_provenance | length), deployments: (.deployments | length), relationships: (.relationships | length)}' \
    demo/golden-vulnerable-ai/ai-bom.json

  echo
  echo "=== LINEAGE / BLAST RADIUS ==="
  MODEL_VERSION_ID=$(jq -r '.model_versions[0].id // empty' demo/golden-vulnerable-ai/ai-bom.json)
  DEPLOYMENT_ID=$(jq -r '.deployments[0].id // empty' demo/golden-vulnerable-ai/ai-bom.json)
  if [ -n "$MODEL_VERSION_ID" ]; then
    PYTHONPATH=src python scripts/aibom_query.py lineage demo/golden-vulnerable-ai/ai-bom.json "$MODEL_VERSION_ID"
  fi
  if [ -n "$DEPLOYMENT_ID" ]; then
    PYTHONPATH=src python scripts/aibom_query.py blast-radius demo/golden-vulnerable-ai/ai-bom.json "$DEPLOYMENT_ID"
  fi
fi

if [ "${SCAN_RC:-0}" -eq 0 ]; then
  echo
  echo "Golden demo completed successfully."
else
  echo
  echo "Golden demo produced the expected non-zero policy/findings exit. See the report and AI-BOM above."
fi

exit "$SCAN_RC"
