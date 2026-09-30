"""Credential material: generation and salted hashing (local only)."""

from __future__ import annotations

import hashlib
import hmac
import secrets

# New credentials look like ``<prefix>_<public-id>.<raw-secret>``.
# The id is stored in clear (it identifies the record); the secret is only
# ever stored as a salted hash.
_SECRET_BYTES = 32
_ID_BYTES = 12
_HASH_SALT = b"local-gateway-v1"


def generate_credential(prefix: str = "cred") -> str:
    """Return a new opaque, high-entropy credential string."""
    public_id = secrets.token_hex(_ID_BYTES)
    raw_secret = secrets.token_urlsafe(_SECRET_BYTES)
    return f"{prefix}_{public_id}.{raw_secret}"


def parse_credential(raw: str) -> tuple[str, str]:
    """Split an opaque credential into (id, secret).

    Raises ``ValueError`` for malformed material.
    """
    if "." not in raw:
        raise ValueError("malformed credential")
    ident, secret = raw.split(".", 1)
    if not ident or not secret:
        raise ValueError("malformed credential")
    return ident, secret


def hash_secret(secret: str, salt: str = "local-gateway") -> str:
    """Deterministic salted SHA-256 hex digest of a secret."""
    digest = hashlib.pbkdf2_hmac(
        "sha256", secret.encode("utf-8"), _HASH_SALT + salt.encode("utf-8"), 100_000
    )
    return digest.hex()


def verify_secret(secret: str, secret_hash: str) -> bool:
    """Constant-time comparison of a secret against its hash."""
    candidate = hash_secret(secret)
    return hmac.compare_digest(candidate, secret_hash)
