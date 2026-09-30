"""Hashing, secret generation and constant-time verification.

* API key secrets are stored with PBKDF2-HMAC-SHA256 (they are long-lived and
  human-managed).
* Access/refresh tokens are high-entropy random strings; only their SHA-256
  digest is stored.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets

_PBKDF2_ROUNDS = 200_000
_PBKDF2_ALGO = "sha256"


def generate_secret(nbytes: int = 32) -> str:
    """Return a URL-safe random secret."""
    return secrets.token_urlsafe(nbytes)


def hash_secret(secret: str) -> str:
    salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac(
        _PBKDF2_ALGO, secret.encode("utf-8"), salt, _PBKDF2_ROUNDS
    )
    return f"pbkdf2_{_PBKDF2_ALGO}${_PBKDF2_ROUNDS}${salt.hex()}${derived.hex()}"


def verify_secret(secret: str, stored: str) -> bool:
    try:
        scheme, rounds_raw, salt_hex, hash_hex = stored.split("$", 3)
        if not scheme.startswith("pbkdf2_"):
            return False
        algo = scheme.split("_", 1)[1]
        rounds = int(rounds_raw)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, TypeError):
        return False
    candidate = hashlib.pbkdf2_hmac(
        algo, secret.encode("utf-8"), salt, rounds
    )
    return hmac.compare_digest(candidate, expected)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
