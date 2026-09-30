"""Stored credential records and request/response schemas."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ApiKeyRecord:
    key_id: str
    secret_hash: str
    scopes: frozenset[str]
    issued_at: datetime
    expires_at: datetime | None
    revoked: bool = False


@dataclass
class AccessTokenRecord:
    token_hash: str
    family_id: str
    scopes: frozenset[str]
    issued_at: datetime
    expires_at: datetime
    revoked: bool = False


@dataclass
class RefreshTokenRecord:
    token_hash: str
    family_id: str
    scopes: frozenset[str]
    issued_at: datetime
    expires_at: datetime
    consumed: bool = False
    revoked: bool = False


@dataclass
class TokenFamily:
    family_id: str
    revoked: bool = False
    #: "reuse" (refresh replay detected) or "admin" (explicit revocation).
    revoke_reason: str | None = None
    lineage: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class LegacyCredential:
    identifier: str
    scopes: frozenset[str]


@dataclass(frozen=True)
class Principal:
    """The authenticated caller as seen by the authorization layer."""

    identity: str
    scopes: frozenset[str]
    legacy: bool = False
