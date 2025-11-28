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
