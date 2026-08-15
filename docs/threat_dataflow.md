# Threat / Risk Data Flow

```mermaid
graph LR
  SBOM["SBOM / Manifests / Lockfiles"] --> Normalize["Normalize & Parse"]
  Models["Model artifacts / models.json"] --> Normalize
  Intel["Threat intel / OSV / Model DBs"] --> Normalize
  Normalize --> Engine["Deterministic Risk Engine"]
  Engine --> Policy["Policy Decision (block/allow/waive)"]
  Engine --> Graph["Evidence Graph (context & relationships)"]
  Policy --> Output["Report / CI Checks / Evidence Bundle"]
  Graph --> Output
```

Notes:
- The deterministic engine evaluates normalized inputs and produces findings and a score.
- The evidence graph is used for impact analysis and explanation; it does not change the deterministic score.
- CI gates consume the policy decision and evidence bundle for enforcement.