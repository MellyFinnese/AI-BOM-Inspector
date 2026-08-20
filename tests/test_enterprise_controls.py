from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aibom_inspector.audit_retention import AuditRetentionPolicy, export_audit_log, purge_audit_entries
from aibom_inspector.enterprise_identity import (
    IdentityError,
    InMemorySCIMDirectory,
    OIDCConfig,
    SAMLConfig,
    build_scim_user,
    identity_from_claims,
    scim_user_from_payload,
    validate_oidc_claims,
    validate_saml_settings,
)
from aibom_inspector.enterprise_secrets import CredentialPolicy, issue_short_lived, should_rotate
from aibom_inspector.mfa import MFAError, MFAPolicy, enforce_mfa_claims, verify_totp
from aibom_inspector.network_policy import NetworkPolicy, NetworkPolicyViolation


def test_oidc_claims_require_issuer_audience_exp_and_mfa() -> None:
    config = OIDCConfig(issuer="https://issuer.example", audience="aibom", mfa_policy=MFAPolicy(required=True))
    now = 1_700_000_000
    claims = {
        "iss": config.issuer,
        "aud": config.audience,
        "sub": "user-1",
        "tenant_id": "tenant-1",
        "exp": now + 60,
        "iat": now - 10,
        "amr": ["otp"],
        "roles": ["security_analyst"],
    }
    validate_oidc_claims(config, claims, now=now)
    identity = identity_from_claims(claims)
    assert identity.mfa_verified is True


def test_oidc_claims_fail_without_mfa() -> None:
    config = OIDCConfig(issuer="https://issuer.example", audience="aibom", mfa_policy=MFAPolicy(required=True))
    with pytest.raises(IdentityError):
        validate_oidc_claims(config, {"iss": config.issuer, "aud": config.audience, "exp": 2_000_000_000}, now=1_700_000_000)


def test_saml_requires_https_and_certificate() -> None:
    with pytest.raises(IdentityError):
        validate_saml_settings(SAMLConfig("sp", "http://example.test/acs", "idp", "cert"))


def test_scim_disable_propagates() -> None:
    directory = InMemorySCIMDirectory()
    user = scim_user_from_payload(
        {"id": "u1", "userName": "alice", "active": True, "emails": [{"value": "alice@example.test"}]},
        tenant_id="tenant-1",
    )
    directory.upsert_user(user)
    directory.deactivate_user("u1")
    assert directory.get_user("u1") is not None
    assert directory.get_user("u1").active is False
    assert build_scim_user(directory.get_user("u1"))['active'] is False


def test_totp_and_recent_mfa_policy() -> None:
    assert verify_totp(b"12345678901234567890", "071711", now=59)
    with pytest.raises(MFAError):
        enforce_mfa_claims(amr=["pwd"], auth_time=1_000, policy=MFAPolicy(), now=1_001)
    enforce_mfa_claims(amr=["webauthn"], auth_time=1_001, policy=MFAPolicy(), now=1_002)


def test_short_lived_credentials_and_rotation() -> None:
    policy = CredentialPolicy(max_ttl_seconds=300, rotation_interval_seconds=60)
    lease = issue_short_lived(lambda: "ephemeral", ttl_seconds=120, policy=policy)
    assert 0 < lease.expires_at
    assert should_rotate(1_000, policy, now=1_061)
    with pytest.raises(Exception):
        issue_short_lived(lambda: "bad", ttl_seconds=301, policy=policy)


def test_network_policy_denies_private_destinations() -> None:
    policy = NetworkPolicy(allowed_egress_ports=(443,))
    with pytest.raises(NetworkPolicyViolation):
        policy.authorize_egress("https://127.0.0.1/")


def test_audit_export_and_retention(tmp_path: Path) -> None:
    source = tmp_path / "audit.jsonl"
    old = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
    recent = datetime.now(timezone.utc).isoformat()
    source.write_text(
        '{"timestamp":"' + old + '","action":"old"}\n' + '{"timestamp":"' + recent + '","action":"new"}\n',
        encoding="utf-8",
    )
    removed = purge_audit_entries(source, policy=AuditRetentionPolicy(retention_days=365))
    assert removed == 1
    exported = export_audit_log(source, tmp_path / "audit-export.jsonl")
    assert exported.suffix == ".gz"
