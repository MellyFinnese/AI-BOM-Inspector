# Contributing to AI-BOM Inspector

Thank you for helping improve AI-BOM Inspector. Contributions should make the project more useful, more secure, more reproducible, or easier to operate.

## Before you start

For substantial changes, open an issue first so the scope and design can be aligned before implementation. Small fixes, documentation improvements, tests, and focused enhancements can go directly to a pull request.

## Development workflow

1. Fork or create a working branch from `main`.
2. Make one focused change at a time.
3. Add or update tests with code changes.
4. Update documentation and examples when behavior or interfaces change.
5. Run the relevant test and quality checks locally.
6. Open a pull request describing the problem, the approach, validation performed, and any security or compatibility considerations.

## Local validation

At minimum, run:

```bash
pytest
```

For changes that affect formatting, typing, packaging, or Rust components, also run the repository's configured lint, type-check, build, and Rust validation commands where applicable.

Do not introduce global exception handling around imports merely to hide missing dependencies. Keep failures explicit and diagnosable.

## What makes a strong contribution

Good contributions generally have:

- a clear security or engineering rationale
- deterministic behavior where determinism is expected
- evidence-backed findings rather than unsupported claims
- bounded resource use for untrusted or large inputs
- regression tests for changed behavior
- documentation that matches the implementation

For detectors and parsers, include representative positive and negative cases. For security-sensitive functionality, include adversarial or abuse-oriented coverage when practical.

## Architecture expectations

Keep the architectural boundary intact:

```text
Evidence / relationships / graph context
                    |
                    v
            deterministic risk
                    |
                    v
              policy / CI
```

The graph/context layer can provide traversal, identity, behavioral change, and impact context, but the deterministic risk engine remains the scoring source of truth.

New integrations should prefer existing backend-neutral interfaces rather than coupling the core engine to one provider.

## Pull requests

PR descriptions should include:

- what changed
- why it changed
- how it was validated
- compatibility or migration notes, if relevant
- security implications, if relevant

Keep commits and PRs reasonably focused. Avoid unrelated formatting churn.

## Security reports

Do **not** open a public issue for a vulnerability or other security-sensitive finding. Follow [`SECURITY.md`](SECURITY.md) instead.

## License

By contributing, you agree that your contribution is provided under the repository's applicable license terms. See [`LICENSE`](LICENSE).
