# Product surface walkthrough

The fastest way to evaluate AI-BOM Inspector should be a single local sequence.

```bash
pip install -e '.[dev]'
PYTHONPATH=src bash demo/golden-vulnerable-ai/run_demo.sh
```

Then inspect JavaScript/TypeScript behavior:

```bash
aibom js-scan benchmarks/javascript/fixtures/reachable-path.ts --output js-analysis.json
aibom behavior-diff benchmarks/javascript/fixtures/agent-tool.ts js-analysis.json
```

Run the quality gate:

```bash
aibom benchmark benchmarks/javascript/manifest.json --fail-below-f1 0.90
```

Finally serve generated reports and demo artifacts:

```bash
aibom serve ./reports --open-browser
```

The intended product loop is therefore:

```text
scan -> evidence -> graph/context -> risk -> drift -> benchmark -> report
```

Nothing in the JavaScript analyzer executes the target repository. The proof is the evidence JSON itself, which is suitable for review and regression testing.
