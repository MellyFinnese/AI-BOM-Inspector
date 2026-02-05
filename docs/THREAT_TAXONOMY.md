# AI threat taxonomy & STRIDE mapping

AI-BOM Inspector uses an explicit AI threat taxonomy to label model findings with human-readable categories, STRIDE classifications, and MITRE ATLAS tactics/techniques. The taxonomy is local-first and configurable via JSON.

## Default taxonomy file

`src/aibom_inspector/data/ai_threat_taxonomy.json` ships with the default mappings. Override it with:

```bash
aibom scan --threat-taxonomy-db path/to/ai_threat_taxonomy.json
```

## Mapping shape

```json
{
  "version": "2024.10",
  "mappings": {
    "MODEL_WEIGHT_ANOMALY": {
      "threats": ["Model poisoning", "Trojaned weights"],
      "stride": ["Tampering"],
      "mitre_atlas": ["AML.TA0004"]
    }
  }
}
```

## How the taxonomy is used

- **STRIDE categories** show up in issue messages and the framework mapping section of reports.
- **MITRE ATLAS codes** (e.g., `AML.TA0004`) surface alongside NIST AI RMF, ISO/IEC 42001, OWASP LLM Top 10, and SOC 2 mappings.
- **Threat labels** provide short, consistent language for triage playbooks and CI gate explanations.

## Extend it locally

1. Add new issue codes to `mappings` (matching the issue codes in your reports).
2. Provide `threats`, `stride`, and `mitre_atlas` arrays.
3. Pass the file to `--threat-taxonomy-db` in CI to keep policy and reporting in sync.
