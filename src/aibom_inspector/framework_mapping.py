from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class FrameworkMapping:
    framework: str
    control: str


_BASE_MAPPINGS: dict[str, list[FrameworkMapping]] = {
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


def _normalize_code(code: str | None, message: str | None) -> str:
    if code:
        return str(code).strip().upper()
    if message:
        return str(message).strip().upper()
    return ""


def framework_mappings_for_issue(code: str | None, message: str | None) -> list[FrameworkMapping]:
    token = _normalize_code(code, message)
    mappings: list[FrameworkMapping] = []

    for key, values in _BASE_MAPPINGS.items():
        if key in token:
            mappings.extend(values)

    if "CVE" in token and not any(mapping.framework == "NIST AI RMF" for mapping in mappings):
        mappings.extend(_BASE_MAPPINGS["CVE"])

    unique: dict[tuple[str, str], FrameworkMapping] = {}
    for mapping in mappings:
        unique[(mapping.framework, mapping.control)] = mapping
    return list(unique.values())


def serialize_mappings(mappings: Iterable[FrameworkMapping]) -> list[dict[str, str]]:
    return [{"framework": m.framework, "control": m.control} for m in mappings]
