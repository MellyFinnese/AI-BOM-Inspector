# AI Supply Chain Threat Model

Enterprises buy governance tooling to mitigate explicit, high-impact risks. This threat model maps AI-specific risks to the detection and control capabilities of AI-BOM Inspector.

## Threat taxonomy

### 1) Model provenance risks

**Threats**
- Unknown or unverifiable model origin
- Untrusted pre-trained checkpoints
- Model tampering during distribution

**Business impact**
- IP contamination
- Regulatory non-compliance
- Undetected backdoors

**Inspector controls**
- Model fingerprinting
- Source attribution
- Signed AI-BOM artifacts

---

### 2) Training data risks

**Threats**
- Unlicensed or restricted data
- Data poisoning
- Sensitive data inclusion (PII/PHI)

**Business impact**
- Legal exposure
- Model manipulation
- Privacy violations

**Inspector controls**
- Training data declarations
- License classification
- Policy enforcement on data sources

---

### 3) Dependency & framework risks

**Threats**
- Vulnerable ML libraries
- Transitive dependency drift
- Unsupported frameworks

**Business impact**
- Exploitable attack surface
- Operational instability

**Inspector controls**
- Dependency SBOM integration
- Advisory correlation
- Version risk scoring

---

### 4) Model behavior & runtime risks

**Threats**
- Prompt injection
- Tool abuse
- Model update drift

**Business impact**
- Unauthorized actions
- Data leakage
- Compliance violations

**Inspector controls (phased)**
- Runtime metadata ingestion
- Model version tracking
- Behavior policy constraints

---

### 5) Deployment & supply chain risks

**Threats**
- Shadow AI deployments
- Environment misconfiguration
- Inconsistent controls across environments

**Business impact**
- Loss of governance
- Audit failure

**Inspector controls**
- Centralized asset registry
- Environment-aware policies
- Evidence-backed approvals

## Threat → Detection → Control mapping

- **Threat**: Unknown training data source  
  **Detection**: `TRAINING_SOURCE_RISK` issue code  
  **Control**: Policy deny on `training_data.source == "unknown"`

- **Threat**: Model tampering  
  **Detection**: `MODEL_HASH_MALICIOUS` / `MODEL_HASH_INVALID`  
  **Control**: Require signed artifacts + provenance attestations

## Compliance alignment

- **NIST AI RMF**: Govern, Map, Measure, Manage
- **ISO 27001**: Asset management, supplier relationships
- **SOC 2**: Change management, risk assessment

## Usage in reports

- Threat metadata is attached to issue codes in JSON output under `threat_summary`.
- Use the taxonomy to drive executive dashboards and policy decisions.
