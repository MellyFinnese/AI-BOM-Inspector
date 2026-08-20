# Independent External Validation

AI-BOM Inspector uses independent repositories to test whether its discovery and evidence model behaves sensibly outside its own fixtures.

## Validation target: d01ki/AIBOM-Inspector

Repository:

`https://github.com/d01ki/AIBOM-Inspector`

Local validation copy:

`external-validation/d01ki-AIBOM-Inspector`

The scan was performed offline, locally, and in safe mode against the repository checkout. The goal was to inspect how model references and evidence are classified in a realistic AI-BOM codebase without granting the scanner network access.

### Observed evidence-context distribution

```text
context          count
---------------- -----
test                97
benchmark           18
implementation      22
documentation         2
example              2
production           2
```

Observed production-relevance classification:

```text
production_relevance=false    141
production_relevance=true       2
```

### Why this matters

A model string inside a unit test or benchmark fixture is not equivalent to a model reference in production application code. The scanner now preserves evidence context and production relevance alongside the evidence message.

Example:

```text
[EVIDENCE] discovered in tests/test_precision.py [evidence_context=test] [production_relevance=false]
```

This validation also exposed scanner behavior that was previously too noisy. Those observations became regression work rather than being treated as proof that the original implementation was correct.

## Validation method

For every external repository used as a validation target, record:

- repository and revision
- scan mode and security boundary
- discovered evidence counts
- context distribution
- production-relevance distribution
- false positives and false negatives, where ground truth exists
- limitations and unsupported semantics

External validation is not a claim of universal detection coverage. It is a repeatable way to expose blind spots in repositories that were not authored as first-party fixtures.

## Reproduction

From the AI-BOM Inspector repository:

```bash
cd ~/AI-BOM-Inspector
source .venv/bin/activate

cd external-validation/d01ki-AIBOM-Inspector

PYTHONPATH=~/AI-BOM-Inspector/src \
python -m aibom_inspector scan \
  --format json \
  --output ~/AI-BOM-Inspector/external-validation/d01ki-full-scan.json \
  --offline \
  --local-only \
  --safe-mode \
  --require-input
```

Inspect the resulting evidence-context labels:

```bash
cd ~/AI-BOM-Inspector

grep -n "evidence_context" \
  external-validation/d01ki-full-scan.json | head -30
```

And summarize the observed classes:

```bash
python - <<'PY'
import re
from collections import Counter

p = "external-validation/d01ki-full-scan.json"
text = open(p, encoding="utf-8").read()

print("Contexts:")
for key, value in Counter(re.findall(r"\[evidence_context=([a-z_]+)\]", text)).items():
    print(f"  {key}: {value}")

print("\nProduction relevance:")
for key, value in Counter(re.findall(r"\[production_relevance=(true|false)\]", text)).items():
    print(f"  {key}: {value}")
PY
```
