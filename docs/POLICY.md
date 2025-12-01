# Policy enforcement

Policies let teams codify their risk appetite for dependencies and models. They are YAML documents that match `schemas/policy.schema.json` and can be loaded with `aibom_inspector.policy.load_policy`.

## Fields

- `min_score` – minimum acceptable stack risk score (0–100).
- `max_cves` – number of CVE/advisory hits allowed before failing.
- `disallow`/`blocklist` – issue codes that should immediately fail policy checks (e.g., `MISSING_PIN`, `UNVERIFIED_SOURCE`).
- `min_trust_score` – minimum trust score for dependencies/models (0–100).
- `publisher_expectations` – map of component names to expected publishers or sources.
- `exceptions` – allowlist entries that can soften strict rules with optional expiration timestamps.

## Examples

Starter policies live in `policies/examples/`:

- `default.yml` sets modest minimum scores and disallows unpinned dependencies.
- `strict.yml` blocks unverified sources, stale models, and unknown licenses.
- `oss-friendly.yml` favors permissive defaults while still rejecting known vulnerabilities.

## GitHub checks

Use `aibom_inspector.policy.write_github_check` to emit a JSON payload suitable for GitHub Checks API integrations. The helper includes the evaluation outcome, stack risk score, and a compact summary of failures.

## Graph-based enforcement

Once auto-discovery completes you have a graph of the AI stack: nodes (agents, tools, models, providers, MCP servers, vector databases, data sources, secrets, runtimes), edges (agent → tool, tool → filesystem path, tool → HTTP request, RAG → datasource, model → provider), and metadata (permissions, URL patterns, filesystem scopes, model versions, evidence, confidence). Policies are constraints over this graph: if a forbidden pattern exists, fail or warn.

### Enforceable policy examples

- **No MCP server with write scope in prod**
  - Rule: if `env == prod` and any `MCPServer` has `write == true`, deny.
  - Evidence to collect: permissions array, environment (from CI/flags), and where the permission was defined (file/line/config key).
  - Remediation to suggest: split a read-only prod variant, enforce per-environment overrides, or require human approval for write-scoped servers.

- **No tool calling + broad filesystem access**
  - Rule: deny tools that combine tool-calling with `fs.write` on `/`, `~`, globs like `**/*`, or temp + executable paths; deny agents that can call tools with `exec.shell` in prod; warn on tools reading sensitive paths (e.g., `.env`, SSH keys).
  - Evidence to collect: capability flags (`fs.read`, `fs.write`, `exec.shell`, `net.egress`), explicit allowlists, and path strings from code/config.
  - Remediation to suggest: sandbox directories (`/var/app/workdir`), explicit allowlists (e.g., `/data/incoming`), or human-in-the-loop for writes outside narrow scopes.

- **No unpinned model IDs**
  - Rule: in prod, model references must be pinned to versioned IDs, provider deployments, or immutable aliases; warn (not fail) in dev/staging.
  - Evidence to collect: `model.id`, `model.version`, provider endpoint/deployment, and where the reference was defined.
  - Remediation to suggest: an internal registry mapping aliases to deployments, and forbidding `latest` or bare family names in prod configs.

### Policy context

Rules need environment context to avoid one-size-fits-all enforcement. Accept a context object such as `--env prod|staging|dev`, `--ci github-actions|gitlab|local`, `--repo-trust public|internal`, and `--data-classification pii|phi|spii|public`; policies can branch on these inputs to tighten prod while remaining informative in dev.

### Implementation guidance

1. Normalize extracted facts into a stable JSON schema so detection results remain backward compatible.
2. Evaluate policies via OPA/Rego, CEL, or a lightweight YAML DSL; choose the engine that fits your UX and maintenance appetite.
3. Emit violations with id, severity, message, evidence entries, and suggested fixes.
4. Add waivers (e.g., `waivers.yml`) with justification, owner, and expiry; expired waivers should fail the build.

### High-signal defaults

Prod deny list:
- Write-scoped MCP servers.
- Shell/exec tools accessible to agents.
- Tools with broad filesystem write or unrestricted network egress.
- Unpinned models.

Prod require list:
- At least one guardrail when tool-calling exists (human approval, sandboxing, or strict allowlists).
- Secrets never reachable by tools (path and env-var denylists).

Warnings:
- RAG sources that include public internet or unknown domains.
- Vector DB persistence without encryption or access controls (when detectable).
- Agents with memory when data is classified as sensitive.
