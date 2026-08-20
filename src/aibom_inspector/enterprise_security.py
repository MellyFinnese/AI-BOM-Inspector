from __future__ import annotations

import os
import re
from dataclasses import dataclass
from enum import Enum


class Role(str, Enum):
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    DEVELOPER = "developer"
    AUDITOR = "auditor"
    READ_ONLY = "read_only"


class Permission(str, Enum):
    READ = "read"
    SCAN = "scan"
    EXPORT = "export"
    POLICY_READ = "policy.read"
    POLICY_WRITE = "policy.write"
    GRAPH_QUERY = "graph.query"
    AUDIT_READ = "audit.read"
    ADMIN = "admin"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.ADMIN: frozenset(Permission),
    Role.SECURITY_ANALYST: frozenset(
        {Permission.READ, Permission.SCAN, Permission.EXPORT, Permission.POLICY_READ, Permission.GRAPH_QUERY, Permission.AUDIT_READ}
    ),
    Role.DEVELOPER: frozenset(
        {Permission.READ, Permission.SCAN, Permission.EXPORT, Permission.POLICY_READ, Permission.GRAPH_QUERY}
    ),
    Role.AUDITOR: frozenset(
        {Permission.READ, Permission.EXPORT, Permission.POLICY_READ, Permission.GRAPH_QUERY, Permission.AUDIT_READ}
    ),
    Role.READ_ONLY: frozenset({Permission.READ}),
}


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: frozenset[Role]
    tenant_id: str
    workspace_id: str | None = None
    authentication_method: str = "external-idp"

    def can(self, permission: Permission) -> bool:
        return any(permission in ROLE_PERMISSIONS[role] for role in self.roles)


def authorize(principal: Principal, permission: Permission, *, tenant_id: str) -> None:
    if principal.tenant_id != tenant_id:
        raise PermissionError("tenant isolation violation")
    if not principal.can(permission):
        raise PermissionError(f"principal is not authorized for {permission.value}")


@dataclass(frozen=True)
class SecretReference:
    provider: str
    reference: str
    env_var: str | None = None

    def validate(self) -> None:
        if self.provider not in {
            "env",
            "vault",
            "aws-secrets-manager",
            "gcp-secret-manager",
            "azure-key-vault",
        }:
            raise ValueError(f"unsupported secret provider: {self.provider}")
        if self.provider == "env":
            if not self.env_var or not re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", self.env_var):
                raise ValueError("env secret references require a valid uppercase environment variable")
        elif not self.reference or any(ch in self.reference for ch in "\r\n"):
            raise ValueError("secret references must be non-empty and single-line")


def resolve_secret(reference: SecretReference) -> str:
    """Resolve supported secret references without accepting raw credential literals."""
    reference.validate()
    if reference.provider == "env":
        value = os.getenv(reference.env_var or "")
        if not value:
            raise RuntimeError(f"required secret environment variable is not set: {reference.env_var}")
        return value
    raise RuntimeError(f"external secret provider '{reference.provider}' requires an enterprise secrets adapter")


def redact(value: str | None) -> str | None:
    if value is None:
        return None
    if len(value) <= 8:
        return "[REDACTED]"
    return f"{value[:4]}…{value[-4:]}"
