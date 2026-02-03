from __future__ import annotations

from dataclasses import dataclass, field

from .dependency_scanner import _infer_registry
from .types import DependencyInfo, DependencyIssue


PUBLIC_REGISTRIES = {"pypi", "npm", "maven", "go"}


@dataclass
class TrustEnforcementConfig:
    trusted_registries: list[str] = field(default_factory=list)
    protected_namespaces: list[str] = field(default_factory=list)
    require_dependency_signatures: bool = False


def _matches_namespace(name: str, namespace: str) -> bool:
    name_lower = name.lower()
    namespace_lower = namespace.lower()
    return name_lower == namespace_lower or name_lower.startswith(namespace_lower)


def apply_dependency_trust_enforcement(
    dependencies: list[DependencyInfo],
    config: TrustEnforcementConfig,
) -> None:
    allowlist = {entry.lower() for entry in config.trusted_registries}
    namespaces = [entry for entry in config.protected_namespaces if entry]

    for dep in dependencies:
        if not dep.registry:
            dep.registry = _infer_registry(dep)
        registry = dep.registry or "unknown"

        if allowlist and registry.lower() not in allowlist:
            dep.issues.append(
                DependencyIssue(
                    f"[REGISTRY_NOT_ALLOWED] Dependency registry '{registry}' not in allowlist",
                    severity="high",
                    code="REGISTRY_NOT_ALLOWED",
                )
            )

        if config.require_dependency_signatures and dep.signature_verified is not True:
            dep.issues.append(
                DependencyIssue(
                    "[DEPENDENCY_SIGNATURE_MISSING] Dependency signature missing or unverified",
                    severity="high",
                    code="DEPENDENCY_SIGNATURE_MISSING",
                )
            )

        for namespace in namespaces:
            if _matches_namespace(dep.name, namespace) and registry.lower() in PUBLIC_REGISTRIES:
                dep.issues.append(
                    DependencyIssue(
                        f"[DEPENDENCY_CONFUSION_RISK] {dep.name} matches protected namespace '{namespace}'",
                        severity="high",
                        code="DEPENDENCY_CONFUSION_RISK",
                    )
                )
                break
