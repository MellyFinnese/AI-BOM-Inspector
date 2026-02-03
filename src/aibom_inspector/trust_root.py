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

    def as_dict(self) -> dict:
        return {
            "key_id": self.key_id,
            "secret": self.secret,
            "algorithm": self.algorithm,
            "created_at": self.created_at,
        }


def create_trust_root() -> TrustRoot:
    key_id = secrets.token_hex(8)
    secret = secrets.token_hex(32)
    return TrustRoot(key_id=key_id, secret=secret, created_at=datetime.utcnow().isoformat())


def load_trust_root(path: Path) -> TrustRoot:
    data = json.loads(path.read_text())
    return TrustRoot(
        key_id=str(data.get("key_id", "")),
        secret=str(data.get("secret", "")),
        algorithm=str(data.get("algorithm", "hmac-sha256")),
        created_at=data.get("created_at"),
    )


def write_trust_root(path: Path, trust_root: TrustRoot) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(trust_root.as_dict(), indent=2))


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sign_payload(payload: dict, trust_root: TrustRoot) -> str:
    message = _canonical_json(payload)
    return hmac.new(trust_root.secret.encode(), message, sha256).hexdigest()


def verify_payload(payload: dict, signature: str, trust_root: TrustRoot) -> bool:
    expected = sign_payload(payload, trust_root)
    return hmac.compare_digest(expected, signature)
