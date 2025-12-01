# GitHub Action integration

Use the composite action in this directory to scan pull requests and post a risk summary. The action expects the repository to be checked out and requires a `GITHUB_TOKEN` with `pull-requests: write` permission.

```yaml
jobs:
  scan-ai-stack:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run AI-BOM Inspector and comment
        uses: ./integrations/github-action
        with:
          manifest: "requirements.txt,pyproject.toml"
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

The workflow `.github/workflows/scan-pr.yml` wires this action up for `pull_request` events by default.

## Example: upload SARIF + Markdown in one call

When you want findings in the GitHub Security tab **and** a human-friendly artifact, emit both formats from a single scan step:

```yaml
name: ai-bom
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install AI-BOM Inspector
        run: pip install aibom-inspector
      - name: Scan and emit SARIF + Markdown
        run: >-
          aibom scan --format sarif --output aibom-report.sarif --markdown-output aibom-report.md
          --fail-on-score 75 --require-input
      - name: Upload SARIF to Security tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: aibom-report.sarif
      - name: Upload Markdown artifact
        uses: actions/upload-artifact@v4
        with:
          name: aibom-report
          path: aibom-report.md
```
