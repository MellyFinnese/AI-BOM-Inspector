# pre-commit integration

Wire the scanner into `pre-commit` by referencing the hook definition in this directory:

```yaml
repos:
  - repo: local
    hooks:
      - id: aibom-scan
        name: AI-BOM Inspector
        entry: python -m aibom_inspector.cli scan --require-input --format json --output /tmp/aibom-report.json
        language: python
        additional_dependencies:
          - aibom-inspector
        pass_filenames: false
```

The hook runs in offline mode by default. Pass manifests explicitly in your project-level configuration (e.g., `args: ["--manifest", "requirements.txt"]`) to avoid scanning unrelated paths.
