from __future__ import annotations

import os

import pytest

from aibom_inspector.enterprise_security import (
    Permission,
    Principal,
    Role,
    SecretReference,
    authorize,
    redact,
    resolve_secret,
)


def test_roles_are_least_privilege() -> None:
    auditor = Principal("alice", frozenset({Role.AUDITOR}), "tenant-a")
    assert auditor.can(Permission.AUDIT_READ)
    assert not auditor.can(Permission.POLICY_WRITE)


def test_tenant_isolation_is_enforced() -> None:
    principal = Principal("alice", frozenset({Role.ADMIN}), "tenant-a")
    with pytest.raises(PermissionError, match="tenant isolation"):
        authorize(principal, Permission.READ, tenant_id="tenant-b")


def test_env_secret_reference_does_not_embed_secret() -> None:
    os.environ["AIBOM_TEST_SECRET"] = "super-secret-value"
    reference = SecretReference("env", "ignored", env_var="AIBOM_TEST_SECRET")
    assert resolve_secret(reference) == "super-secret-value"
    assert redact("super-secret-value") == "supe…alue"


def test_external_secret_providers_fail_closed_until_adapter_is_configured() -> None:
    with pytest.raises(RuntimeError, match="requires an enterprise secrets adapter"):
        resolve_secret(SecretReference("vault", "secret/data/aibom"))
