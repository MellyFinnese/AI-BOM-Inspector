from __future__ import annotations

import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from pathlib import Path


@dataclass(frozen=True)
class TrustRoot:
    key_id: str
    secret: str
    algorithm: str = "hmac-sha256"
    created_at: str | None = None
    signature: str | None = None
    fingerprint: str | None = None

    def public_metadata(self) -> dict:
        return {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "created_at": self.created_at,
        }

    def as_dict(self) -> dict:
        payload = {
            "key_id": self.key_id,
            "secret": self.secret,
            "algorithm": self.algorithm,
            "created_at": self.created_at,
            "signature": self.signature,
            "fingerprint": self.fingerprint,
        }
        return payload


def create_trust_root() -> TrustRoot:
    key_id = secrets.token_hex(8)
    secret = secrets.token_hex(32)
    created_at = datetime.utcnow().isoformat()
    fingerprint = _fingerprint_payload({"key_id": key_id, "created_at": created_at})
    root = TrustRoot(
        key_id=key_id,
        secret=secret,
        created_at=created_at,
        fingerprint=fingerprint,
    )
    signature = sign_trust_root(root)
    return TrustRoot(
        key_id=root.key_id,
        secret=root.secret,
        algorithm=root.algorithm,
        created_at=root.created_at,
        fingerprint=root.fingerprint,
        signature=signature,
    )


def load_trust_root(path: Path) -> TrustRoot:
    data = json.loads(path.read_text())
    return TrustRoot(
        key_id=str(data.get("key_id", "")),
        secret=str(data.get("secret", "")),
        algorithm=str(data.get("algorithm", "hmac-sha256")),
        created_at=data.get("created_at"),
        signature=data.get("signature"),
        fingerprint=data.get("fingerprint"),
    )


def write_trust_root(path: Path, trust_root: TrustRoot) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(trust_root.as_dict(), indent=2))


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _fingerprint_payload(payload: dict) -> str:
    return sha256(_canonical_json(payload)).hexdigest()


def sign_payload(payload: dict, trust_root: TrustRoot) -> str:
    message = _canonical_json(payload)
    return hmac.new(trust_root.secret.encode(), message, sha256).hexdigest()


def verify_payload(payload: dict, signature: str, trust_root: TrustRoot) -> bool:
    expected = sign_payload(payload, trust_root)
    return hmac.compare_digest(expected, signature)


def sign_trust_root(trust_root: TrustRoot) -> str:
    return sign_payload(trust_root.public_metadata(), trust_root)


def verify_trust_root(trust_root: TrustRoot) -> bool:
    if not trust_root.signature:
        return False
    return verify_payload(trust_root.public_metadata(), trust_root.signature, trust_root)


def trust_root_fingerprint(trust_root: TrustRoot) -> str:
    payload = trust_root.public_metadata()
    return trust_root.fingerprint or _fingerprint_payload(payload)
