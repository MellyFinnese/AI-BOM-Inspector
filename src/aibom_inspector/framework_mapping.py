from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class FrameworkMapping:
    framework: str
    control: str


_BUILTIN_MAPPINGS: dict[str, list[FrameworkMapping]] = {
    "MISSING_PIN": [
        FrameworkMapping("NIST AI RMF", "GOVERN 1.6"),
        FrameworkMapping("ISO/IEC 42001", "A.5.3"),
        FrameworkMapping("SOC 2", "CC8.1"),
    ],
    "LOOSE_PIN": [
        FrameworkMapping("NIST AI RMF", "GOVERN 1.6"),
        FrameworkMapping("ISO/IEC 42001", "A.5.3"),
        FrameworkMapping("SOC 2", "CC8.1"),
    ],
    "UNVERIFIED_SOURCE": [
        FrameworkMapping("NIST AI RMF", "MAP 1.4"),
        FrameworkMapping("ISO/IEC 42001", "A.6.7"),
        FrameworkMapping("OWASP LLM Top 10", "LLM05"),
        FrameworkMapping("SOC 2", "CC5.2"),
    ],
    "UNKNOWN_LICENSE": [
        FrameworkMapping("NIST AI RMF", "GOVERN 1.2"),
        FrameworkMapping("ISO/IEC 42001", "A.5.2"),
        FrameworkMapping("SOC 2", "CC1.2"),
    ],
    "STALE_MODEL": [
        FrameworkMapping("NIST AI RMF", "MEASURE 2.2"),
        FrameworkMapping("ISO/IEC 42001", "A.7.4"),
        FrameworkMapping("OWASP LLM Top 10", "LLM09"),
    ],
    "KNOWN_VULN": [
        FrameworkMapping("NIST AI RMF", "GOVERN 1.6"),
        FrameworkMapping("ISO/IEC 42001", "A.6.8"),
        FrameworkMapping("OWASP LLM Top 10", "LLM06"),
        FrameworkMapping("SOC 2", "CC7.1"),
    ],
    "CVE": [
        FrameworkMapping("NIST AI RMF", "GOVERN 1.6"),
        FrameworkMapping("ISO/IEC 42001", "A.6.8"),
        FrameworkMapping("OWASP LLM Top 10", "LLM06"),
        FrameworkMapping("SOC 2", "CC7.1"),
    ],
    "MODEL_VULNERABILITY": [
        FrameworkMapping("NIST AI RMF", "GOVERN 1.6"),
        FrameworkMapping("ISO/IEC 42001", "A.6.8"),
        FrameworkMapping("OWASP LLM Top 10", "LLM06"),
        FrameworkMapping("MITRE ATLAS", "AML.TA0004"),
        FrameworkMapping("SOC 2", "CC7.1"),
    ],
    "MODEL_HASH_MALICIOUS": [
        FrameworkMapping("NIST AI RMF", "MAP 1.4"),
        FrameworkMapping("ISO/IEC 42001", "A.6.4"),
        FrameworkMapping("MITRE ATLAS", "AML.TA0004"),
        FrameworkMapping("SOC 2", "CC7.1"),
    ],
    "MODEL_WEIGHT_ANOMALY": [
        FrameworkMapping("NIST AI RMF", "MEASURE 2.2"),
        FrameworkMapping("ISO/IEC 42001", "A.7.4"),
        FrameworkMapping("MITRE ATLAS", "AML.TA0004"),
    ],
    "PICKLE_DANGEROUS_GLOBALS": [
        FrameworkMapping("NIST AI RMF", "MAP 1.4"),
        FrameworkMapping("ISO/IEC 42001", "A.6.4"),
        FrameworkMapping("MITRE ATLAS", "AML.TA0005"),
        FrameworkMapping("SOC 2", "CC7.1"),
    ],
    "MODEL_LICENSE_RESTRICTED": [
        FrameworkMapping("NIST AI RMF", "GOVERN 1.2"),
        FrameworkMapping("ISO/IEC 42001", "A.5.2"),
        FrameworkMapping("SOC 2", "CC1.2"),
    ],
    "PROPRIETARY_AI_RISK": [
        FrameworkMapping("NIST AI RMF", "GOVERN 1.2"),
        FrameworkMapping("ISO/IEC 42001", "A.5.2"),
        FrameworkMapping("SOC 2", "CC1.2"),
        FrameworkMapping("EU AI Act", "Transparency"),
    ],
    "MODEL_LINEAGE_RISK": [
        FrameworkMapping("NIST AI RMF", "MAP 1.4"),
        FrameworkMapping("ISO/IEC 42001", "A.6.4"),
        FrameworkMapping("SOC 2", "CC7.1"),
        FrameworkMapping("EU AI Act", "Risk management"),
    ],
    "MODEL_LINEAGE_UNKNOWN": [
        FrameworkMapping("NIST AI RMF", "MAP 1.4"),
        FrameworkMapping("ISO/IEC 42001", "A.6.4"),
        FrameworkMapping("SOC 2", "CC7.1"),
        FrameworkMapping("EU AI Act", "Data governance"),
    ],
    "FINE_TUNE_INHERITANCE_RISK": [
        FrameworkMapping("NIST AI RMF", "MEASURE 2.2"),
        FrameworkMapping("ISO/IEC 42001", "A.7.4"),
        FrameworkMapping("SOC 2", "CC7.1"),
        FrameworkMapping("EU AI Act", "Risk management"),
    ],
    "DATASET_CONTAMINATION_RISK": [
        FrameworkMapping("NIST AI RMF", "MAP 1.3"),
        FrameworkMapping("ISO/IEC 42001", "A.6.6"),
        FrameworkMapping("SOC 2", "CC7.2"),
        FrameworkMapping("EU AI Act", "Data governance"),
    ],
    "TRAINING_SOURCE_RISK": [
        FrameworkMapping("NIST AI RMF", "MAP 1.3"),
        FrameworkMapping("ISO/IEC 42001", "A.6.6"),
        FrameworkMapping("SOC 2", "CC7.2"),
        FrameworkMapping("EU AI Act", "Data governance"),
    ],
    "SUPPLY_CHAIN_ANOMALY": [
        FrameworkMapping("NIST AI RMF", "GOVERN 1.6"),
        FrameworkMapping("ISO/IEC 42001", "A.6.8"),
        FrameworkMapping("SOC 2", "CC7.1"),
        FrameworkMapping("EU AI Act", "Risk management"),
    ],
    "MODEL_HASH_INVALID": [
        FrameworkMapping("NIST AI RMF", "GOVERN 1.6"),
        FrameworkMapping("ISO/IEC 42001", "A.6.8"),
        FrameworkMapping("SOC 2", "CC7.1"),
        FrameworkMapping("EU AI Act", "Risk management"),
    ],
    "MODEL_HASH_MISSING": [
        FrameworkMapping("NIST AI RMF", "GOVERN 1.6"),
        FrameworkMapping("ISO/IEC 42001", "A.6.8"),
        FrameworkMapping("SOC 2", "CC7.1"),
        FrameworkMapping("EU AI Act", "Risk management"),
    ],
    "TYPOSQUAT_SUSPECT": [
        FrameworkMapping("NIST AI RMF", "MAP 1.3"),
        FrameworkMapping("ISO/IEC 42001", "A.6.4"),
        FrameworkMapping("OWASP LLM Top 10", "LLM05"),
        FrameworkMapping("SOC 2", "CC5.2"),
    ],
    "SUSPICIOUS_RELEASE": [
        FrameworkMapping("NIST AI RMF", "MAP 1.4"),
        FrameworkMapping("ISO/IEC 42001", "A.6.4"),
        FrameworkMapping("SOC 2", "CC5.2"),
    ],
    "REPO_MISMATCH": [
        FrameworkMapping("NIST AI RMF", "MAP 1.4"),
        FrameworkMapping("ISO/IEC 42001", "A.6.4"),
        FrameworkMapping("SOC 2", "CC5.2"),
    ],
}

_MAPPING_VERSION = "builtin"
_MAPPING_SOURCE = "builtin"


def _load_owned_mappings() -> dict[str, list[FrameworkMapping]] | None:
    global _MAPPING_VERSION, _MAPPING_SOURCE
    candidate = Path(__file__).resolve().parents[2] / "policies" / "framework_mappings.json"
    if not candidate.exists():
        return None
    try:
        data = json.loads(candidate.read_text())
    except Exception:
        return None
    mappings = {}
    raw_mappings = data.get("mappings", {})
    for code, entries in raw_mappings.items():
        mappings[str(code).upper()] = [
            FrameworkMapping(framework=entry["framework"], control=entry["control"])
            for entry in entries
        ]
    _MAPPING_VERSION = str(data.get("version", "owned"))
    _MAPPING_SOURCE = str(candidate)
    return mappings


_OWNED_MAPPINGS = _load_owned_mappings()


def framework_mapping_metadata() -> dict[str, str]:
    return {"version": _MAPPING_VERSION, "source": _MAPPING_SOURCE}


def _normalize_code(code: str | None, message: str | None) -> str:
    if code:
        return str(code).strip().upper()
    if message:
        return str(message).strip().upper()
    return ""


def framework_mappings_for_issue(code: str | None, message: str | None) -> list[FrameworkMapping]:
    token = _normalize_code(code, message)
    mappings: list[FrameworkMapping] = []

    mappings_table = _OWNED_MAPPINGS or _BUILTIN_MAPPINGS
    for key, values in mappings_table.items():
        if key in token:
            mappings.extend(values)

    if "CVE" in token and not any(mapping.framework == "NIST AI RMF" for mapping in mappings):
        mappings.extend(mappings_table.get("CVE", []))

    unique: dict[tuple[str, str], FrameworkMapping] = {}
    for mapping in mappings:
        unique[(mapping.framework, mapping.control)] = mapping
    return list(unique.values())


def serialize_mappings(mappings: Iterable[FrameworkMapping]) -> list[dict[str, str]]:
    return [{"framework": m.framework, "control": m.control} for m in mappings]
