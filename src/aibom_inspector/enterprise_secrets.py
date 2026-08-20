from __future__ import annotations

import json
import secrets as secrets_module
import time
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

import requests


class SecretError(RuntimeError):
    pass


@dataclass(frozen=True)
class SecretLease:
    value: str
    expires_at: int
    lease_id: str | None = None
    renewable: bool = False

    @property
    def remaining_seconds(self) -> int:
        return max(0, self.expires_at - int(time.time()))


class SecretProvider(Protocol):
    def read(self, reference: str) -> SecretLease: ...
    def rotate(self, reference: str, value: str | None = None) -> SecretLease: ...


@dataclass(frozen=True)
class VaultConfig:
    address: str
    token: str
    mount: str = "secret"
    timeout_seconds: float = 10.0


class VaultKVProvider:
    def __init__(self, config: VaultConfig) -> None:
        self.config = config
        if not config.address.startswith(("https://", "http://")):
            raise ValueError("Vault address must be an absolute HTTP(S) URL")
        if not config.token or "\n" in config.token or "\r" in config.token:
            raise ValueError("Vault token must be non-empty and single-line")

    @property
    def _headers(self) -> dict[str, str]:
        return {"X-Vault-Token": self.config.token, "Accept": "application/json"}

    def read(self, reference: str) -> SecretLease:
        url = f"{self.config.address.rstrip('/')}/v1/{self.config.mount}/data/{reference.lstrip('/')}"
        response = requests.get(url, headers=self._headers, timeout=self.config.timeout_seconds)
        response.raise_for_status()
        data = response.json().get("data", {})
        inner = data.get("data", {})
        value = inner.get("value") or inner.get("secret")
        if not isinstance(value, str):
            raise SecretError("Vault secret has no string value")
        metadata = data.get("metadata", {})
        lease = int(metadata.get("deletion_time", "0")[:19].replace("-", "") or 0) if False else 0
        return SecretLease(value=value, expires_at=int(time.time()) + 300, lease_id=metadata.get("version"), renewable=False)

    def rotate(self, reference: str, value: str | None = None) -> SecretLease:
        if value is None:
            value = secrets_module.token_urlsafe(48)
        url = f"{self.config.address.rstrip('/')}/v1/{self.config.mount}/data/{reference.lstrip('/')}"
        response = requests.post(
            url,
            headers=self._headers,
            json={"data": {"value": value}},
            timeout=self.config.timeout_seconds,
        )
        response.raise_for_status()
        version = response.json().get("data", {}).get("version")
        return SecretLease(value=value, expires_at=int(time.time()) + 300, lease_id=str(version) if version else None)


@dataclass(frozen=True)
class KMSConfig:
    provider: str
    key_id: str
    region: str | None = None


def kms_generate_data_key(config: KMSConfig, *, context: Mapping[str, str] | None = None) -> dict[str, Any]:
    context = context or {}
    if config.provider == "aws":
        try:
            import boto3  # type: ignore
        except ImportError as exc:
            raise SecretError("boto3 is required for AWS KMS") from exc
        client = boto3.client("kms", region_name=config.region)
        response = client.generate_data_key(KeyId=config.key_id, KeySpec="AES_256", EncryptionContext=dict(context))
        plaintext = response["Plaintext"]
        return {"plaintext": plaintext, "ciphertext": response["CiphertextBlob"], "key_id": config.key_id}
    raise SecretError(f"unsupported KMS provider: {config.provider}")


@dataclass(frozen=True)
class CredentialPolicy:
    max_ttl_seconds: int = 3600
    rotation_interval_seconds: int = 86400
    require_short_lived: bool = True

    def validate_ttl(self, ttl_seconds: int) -> None:
        if ttl_seconds <= 0 or ttl_seconds > self.max_ttl_seconds:
            raise SecretError(f"credential TTL must be between 1 and {self.max_ttl_seconds} seconds")


def issue_short_lived(value_factory, *, ttl_seconds: int, policy: CredentialPolicy) -> SecretLease:
    policy.validate_ttl(ttl_seconds)
    if not policy.require_short_lived and ttl_seconds == policy.max_ttl_seconds:
        raise SecretError("refusing long-lived credential issuance")
    value = value_factory()
    if not isinstance(value, str) or not value:
        raise SecretError("credential factory returned no credential")
    return SecretLease(value=value, expires_at=int(time.time()) + ttl_seconds, renewable=False)


def should_rotate(created_at: int, policy: CredentialPolicy, *, now: int | None = None) -> bool:
    now = int(time.time()) if now is None else now
    return now - created_at >= policy.rotation_interval_seconds


def redact_secret(value: str) -> str:
    return "[REDACTED]" if len(value) <= 8 else f"{value[:4]}…{value[-4:]}"
