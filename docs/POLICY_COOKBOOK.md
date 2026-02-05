# Policy cookbook

Starter policies you can drop into `policies/` or CI pipelines. Use them as-is or copy the YAML into your own files.

## OSS-friendly (fast adoption)
Reference: `policies/examples/oss-friendly.yml`
- **Fail on unpinned dependencies**: prioritize reproducibility without blocking permissive licenses.
- **Warn on unknown licenses**: highlight missing metadata but do not fail builds while teams backfill.
- **Allow `huggingface` and `openmodel` sources**: keep defaults permissive for open ecosystems.
- **Offline-first**: keep `--offline` as default; only opt into CVE lookups when needed.

## Enterprise-strict (governed defaults)
Reference: `policies/examples/strict.yml`
- **Fail on unknown or copyleft licenses**: require SPDX identifiers for both dependencies and models.
- **Enforce allowlist for model sources**: restrict to `huggingface`, `private`, or `registry` to prevent shadow model usage.
- **Require pins and lockfiles**: gate on `MISSING_PIN`/`LOOSE_PIN` and mandate lockfile presence.
- **Disallow stale models**: flag anything older than the freshness threshold; require explicit waivers in policy.
- **Online enrichment optional**: keep offline by default but recommend `--with-cves` in controlled CI with outbound egress.

## Regulated (audit-ready)
Reference: `policies/examples/default.yml`
- **Attestation-friendly outputs**: export CycloneDX/SPDX alongside JSON for traceability.
- **Strict license hygiene**: block unknown licenses, warn on proprietary, and log waivers in git history.
- **Model provenance**: require `source`, `sha256`, and `last_updated` in `models.json`; treat missing fields as failures.
- **Allowlist enforcement**: only allow curated registries; fail on unverified sources and require `--require-input`.
- **CVE + advisory checks**: encourage `--with-cves` and model advisories where available to keep audit trails complete.

## HIPAA (PHI-focused)
Reference: `policies/examples/hipaa.yml`
- **Zero CVE tolerance**: block any `CVE`/`MODEL_VULNERABILITY` hits before handling PHI.
- **Restrictive sources**: allow only vetted registries and private model sources.
- **Hash-based provenance**: disallow missing model hashes to enforce artifact integrity.

## SOC 2 (trust services)
Reference: `policies/examples/soc2.yml`
- **Availability + security focus**: enforce lockfile checksums and unverified source bans.
- **License governance**: block unknown or restricted model licenses.
- **Audit trail ready**: require approvals for high-risk findings.

## ISO/IEC 42001 (AI management)
Reference: `policies/examples/iso-42001.yml`
- **Risk scoring discipline**: higher minimum stack score and strict CVE caps.
- **Model integrity checks**: block malicious hash matches and unsafe checkpoints.
- **Governance requirements**: enforce graph guardrails in production.

## Policy-forward CI gate (recommended default)
- **Graph guardrails on**: keep `--enforce-graph-policy --env prod` enabled so auto-discovered tools/models/providers are blocked when they carry write scopes or unpinned sources.
- **Readable failures**: wire `--github-check-output` to surface policy violations as PR comments plus SARIF upload for code scanning.
- **Cookbook presets**: start from `policies/examples/strict.yml` and enable exceptions per team via `exceptions:` entries rather than editing the allowlist directly.
- **Fail fast**: pair `--require-input` with `--fail-on-score 70` to avoid "green" runs that never scanned a dependency or model.
