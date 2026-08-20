from __future__ import annotations

import base64
import json
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Mapping

from .mfa import MFAPolicy, enforce_mfa_claims


class IdentityError(RuntimeError):
    pass


class MFARequired(IdentityError):
    pass


class OIDCConfigurationError(IdentityError):
    pass


@dataclass(frozen=True)
class OIDCConfig:
    issuer: str
    audience: str
    required_scopes: frozenset[str] = frozenset()
    mfa_policy: MFAPolicy = MFAPolicy()


@dataclass(frozen=True)
class AuthenticatedIdentity:
    subject: str
    email: str | None
    display_name: str | None
    roles: frozenset[str]
    tenant_id: str
    mfa_verified: bool
    authentication_method: str
    claims: Mapping[str, Any] = field(default_factory=dict)


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def parse_jwt_header(token: str) -> dict[str, Any]:
    try:
        encoded, _, _ = token.split(".", 2)
        return json.loads(_b64url_decode(encoded))
    except Exception as exc:
        raise IdentityError("invalid JWT structure") from exc


def oidc_discovery_url(issuer: str) -> str:
    return issuer.rstrip("/") + "/.well-known/openid-configuration"


def fetch_oidc_discovery(config: OIDCConfig, *, timeout: float = 10.0) -> dict[str, Any]:
    request = urllib.request.Request(oidc_discovery_url(config.issuer), headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise OIDCConfigurationError("unable to load OIDC discovery metadata") from exc
    if payload.get("issuer", "").rstrip("/") != config.issuer.rstrip("/"):
        raise OIDCConfigurationError("OIDC discovery issuer mismatch")
    if "jwks_uri" not in payload:
        raise OIDCConfigurationError("OIDC discovery metadata has no jwks_uri")
    return payload


def verify_oidc_token(token: str, config: OIDCConfig, *, tenant_claim: str = "tenant_id", leeway: int = 30) -> AuthenticatedIdentity:
    """Cryptographically verify an OIDC JWT using the issuer's JWKS and enforce claims/MFA."""
    try:
        import jwt  # type: ignore
        from jwt import PyJWKClient
    except ImportError as exc:
        raise OIDCConfigurationError("PyJWT is required for OIDC token verification") from exc

    metadata = fetch_oidc_discovery(config)
    try:
        signing_key = PyJWKClient(metadata["jwks_uri"]).get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
            audience=config.audience,
            issuer=config.issuer,
            leeway=leeway,
            options={"require": ["sub", "iss", "aud", "exp", "iat"]},
        )
    except Exception as exc:
        raise IdentityError("OIDC signature or claims validation failed") from exc
    validate_oidc_claims(config, claims)
    return identity_from_claims(claims, tenant_claim=tenant_claim)


def validate_oidc_claims(config: OIDCConfig, claims: Mapping[str, Any], *, now: int | None = None) -> None:
    now = int(time.time()) if now is None else now
    issuer = str(claims.get("iss", "")).rstrip("/")
    if issuer != config.issuer.rstrip("/"):
        raise IdentityError("OIDC issuer mismatch")
    audience = claims.get("aud")
    audiences = {audience} if isinstance(audience, str) else set(audience or [])
    if config.audience not in audiences:
        raise IdentityError("OIDC audience mismatch")
    exp = claims.get("exp")
    if not isinstance(exp, int) or exp <= now:
        raise IdentityError("OIDC token is expired")
    if "nbf" in claims and isinstance(claims["nbf"], int) and claims["nbf"] > now:
        raise IdentityError("OIDC token is not yet valid")
    if config.required_scopes:
        granted = set(str(claims.get("scope", "")).split())
        if not config.required_scopes.issubset(granted):
            raise IdentityError("OIDC token is missing required scopes")
    try:
        enforce_mfa_claims(
            amr=claims.get("amr"),
            auth_time=claims.get("auth_time"),
            policy=config.mfa_policy,
            now=now,
            admin="admin" in set(str(v) for v in (claims.get("roles") or [])),
        )
    except PermissionError as exc:
        raise MFARequired(str(exc)) from exc


def identity_from_claims(claims: Mapping[str, Any], *, tenant_claim: str = "tenant_id") -> AuthenticatedIdentity:
    subject = str(claims.get("sub") or "").strip()
    tenant_id = str(claims.get(tenant_claim) or "").strip()
    if not subject or not tenant_id:
        raise IdentityError("OIDC identity is missing subject or tenant")
    roles_raw = claims.get("roles") or claims.get("groups") or []
    if isinstance(roles_raw, str):
        roles = frozenset(v for v in roles_raw.split() if v)
    else:
        roles = frozenset(str(v) for v in roles_raw)
    amr = claims.get("amr") or []
    mfa = any(str(v).lower() in {"mfa", "otp", "totp", "hwk", "webauthn"} for v in amr)
    return AuthenticatedIdentity(
        subject=subject,
        email=str(claims.get("email")) if claims.get("email") else None,
        display_name=str(claims.get("name")) if claims.get("name") else None,
        roles=roles,
        tenant_id=tenant_id,
        mfa_verified=mfa,
        authentication_method="oidc",
        claims=claims,
    )


@dataclass(frozen=True)
class SAMLConfig:
    entity_id: str
    acs_url: str
    idp_entity_id: str
    idp_x509_cert: str
    require_mfa: bool = True


def validate_saml_settings(config: SAMLConfig) -> None:
    if not config.entity_id or not config.acs_url or not config.idp_entity_id or not config.idp_x509_cert.strip():
        raise IdentityError("SAML configuration is incomplete")
    if not config.acs_url.startswith("https://"):
        raise IdentityError("SAML ACS URL must use HTTPS")


def validate_saml_response(config: SAMLConfig, saml_response_b64: str, *, request_data: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Validate a SAML response with python3-saml, including signature and destination checks."""
    validate_saml_settings(config)
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth  # type: ignore
    except ImportError as exc:
        raise OIDCConfigurationError("python3-saml is required for SAML assertion validation") from exc
    try:
        auth_request = {
            "https": "on",
            "http_host": urllib.parse.urlparse(config.acs_url).netloc,
            "server_port": "443",
            "script_name": "/",
            "get_data": {},
            "post_data": {"SAMLResponse": saml_response_b64},
        }
        if request_data:
            auth_request.update(dict(request_data))
        settings = {
            "sp": {
                "entityId": config.entity_id,
                "assertionConsumerService": {"url": config.acs_url, "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"},
            },
            "idp": {"entityId": config.idp_entity_id, "x509cert": config.idp_x509_cert},
            "security": {"wantAssertionsSigned": True, "wantMessagesSigned": True, "rejectUnsolicitedResponsesWithInResponseTo": True},
        }
        auth = OneLogin_Saml2_Auth(auth_request, settings)
        auth.process_response()
        errors = auth.get_errors()
        if errors:
            raise IdentityError("SAML response validation failed: " + ", ".join(errors))
        return {"name_id": auth.get_nameid(), "attributes": auth.get_attributes(), "session_index": auth.get_session_index()}
    except IdentityError:
        raise
    except Exception as exc:
        raise IdentityError("SAML response validation failed") from exc


@dataclass(frozen=True)
class SCIMUser:
    id: str
    user_name: str
    active: bool
    display_name: str | None
    emails: tuple[str, ...]
    groups: tuple[str, ...] = ()
    tenant_id: str = ""


class InMemorySCIMDirectory:
    def __init__(self) -> None:
        self._users: dict[str, SCIMUser] = {}

    def upsert_user(self, user: SCIMUser) -> SCIMUser:
        if not user.id or not user.user_name or not user.tenant_id:
            raise IdentityError("SCIM user requires id, userName and tenant_id")
        self._users[user.id] = user
        return user

    def deactivate_user(self, user_id: str) -> None:
        current = self._users.get(user_id)
        if current:
            self._users[user_id] = SCIMUser(
                id=current.id, user_name=current.user_name, active=False, display_name=current.display_name,
                emails=current.emails, groups=current.groups, tenant_id=current.tenant_id,
            )

    def delete_user(self, user_id: str) -> None:
        self._users.pop(user_id, None)

    def get_user(self, user_id: str) -> SCIMUser | None:
        return self._users.get(user_id)


def scim_user_from_payload(payload: Mapping[str, Any], *, tenant_id: str) -> SCIMUser:
    emails = tuple(str(item.get("value")) for item in (payload.get("emails") or []) if isinstance(item, Mapping) and item.get("value"))
    groups = tuple(str(item.get("value") or item.get("display")) for item in (payload.get("groups") or []) if isinstance(item, Mapping) and (item.get("value") or item.get("display")))
    return SCIMUser(
        id=str(payload.get("id") or ""), user_name=str(payload.get("userName") or ""),
        active=bool(payload.get("active", True)),
        display_name=str(payload.get("displayName")) if payload.get("displayName") else None,
        emails=emails, groups=groups, tenant_id=tenant_id,
    )


def build_scim_user(user: SCIMUser) -> dict[str, Any]:
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "id": user.id,
        "userName": user.user_name, "active": user.active, "displayName": user.display_name,
        "emails": [{"value": email, "primary": index == 0} for index, email in enumerate(user.emails)],
        "groups": [{"value": group} for group in user.groups], "meta": {"resourceType": "User"},
    }
