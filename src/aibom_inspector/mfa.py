from __future__ import annotations

import hashlib
import hmac
import struct
import time
from dataclasses import dataclass


class MFAError(PermissionError):
    pass


@dataclass(frozen=True)
class MFAPolicy:
    required: bool = True
    totp_step_seconds: int = 30
    totp_digits: int = 6
    allowed_drift_steps: int = 1
    require_recent_seconds: int = 300
    require_webauthn_for_admin: bool = False


def verify_totp(secret: bytes | str, code: str, *, policy: MFAPolicy | None = None, now: int | None = None) -> bool:
    policy = policy or MFAPolicy()
    if not code.isdigit() or len(code) != policy.totp_digits:
        return False
    raw_secret = secret.encode() if isinstance(secret, str) else secret
    current = int(time.time()) if now is None else now
    counter = current // policy.totp_step_seconds
    for offset in range(-policy.allowed_drift_steps, policy.allowed_drift_steps + 1):
        message = struct.pack(">Q", counter + offset)
        digest = hmac.new(raw_secret, message, hashlib.sha1).digest()
        position = digest[-1] & 0x0F
        number = struct.unpack(">I", digest[position : position + 4])[0] & 0x7FFFFFFF
        candidate = str(number % (10**policy.totp_digits)).zfill(policy.totp_digits)
        if hmac.compare_digest(candidate, code):
            return True
    return False


def enforce_mfa_claims(*, amr: list[str] | tuple[str, ...] | None, auth_time: int | None, policy: MFAPolicy, now: int | None = None, admin: bool = False) -> None:
    if not policy.required:
        return
    now = int(time.time()) if now is None else now
    methods = {str(item).lower() for item in (amr or ())}
    if not methods.intersection({"mfa", "otp", "totp", "webauthn", "hwk"}):
        raise MFAError("MFA authentication method is required")
    if auth_time is not None and now - auth_time > policy.require_recent_seconds:
        raise MFAError("MFA authentication is too old; re-authentication is required")
    if admin and policy.require_webauthn_for_admin and not methods.intersection({"webauthn", "hwk"}):
        raise MFAError("administrators require phishing-resistant MFA")
