# Framework interpretations (canonical)

AI-BOM Inspector ships a canonical framework mapping registry so governance teams can rely on a stable, owner-controlled interpretation of findings.

## Registry
- **Source of truth**: `policies/framework_mappings.json`
- **Versioned**: `version` field in the registry controls release cadence.
- **Surface area**: every issue includes `frameworks` in report outputs, and report metadata records the mapping version/source.

## Governance intent
These mappings are opinionated to align AI supply-chain findings to governance frameworks consistently across customers. Update the registry when:
- A new issue code is introduced.
- A framework update changes control coverage.
- A customer contract requires a stricter mapping.

## Publishing workflow
1. Update `policies/framework_mappings.json`.
2. Bump the `version` field.
3. Ship a release and update customer-facing documentation.

## Validation
Use the report metadata block to verify which mapping version was applied:

```json
"framework_mapping": {
  "version": "2024.09-owned",
  "source": "policies/framework_mappings.json"
}
```
