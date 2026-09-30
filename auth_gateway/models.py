"""Stored credential records and the authenticated principal."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class CredentialKind(str, Enum):
    API_KEY = "api_key"
    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"
    LEGACY = "legacy"


@dataclass
class ApiKeyRecord:
    key_id: str
    secret_hash: str
    scopes: frozenset[str]
    issued_at: float
    expires_at: float
    revoked: bool = False
    # Rotation/family membership is not needed for plain API keys.
    family_id: str | None = None


@dataclass
class RefreshTokenRecord:
    token_id: str
    family_id: str
    secret_hash: str
    issued_at: float
    expires_at: float
    revoked: bool = False
    # Set when this token has already been exchanged (rotation).
    consumed: bool = False
    # Set when the whole family was invalidated (reuse detected).
    family_revoked: bool = False


@dataclass
class AccessTokenRecord:
    token_id: str
    family_id: str
    secret_hash: str
    scopes: frozenset[str]
    issued_at: float
    expires_at: float
    revoked: bool = False


@dataclass
class FamilyRecord:
    family_id: str
    revoked: bool = False
    revoke_reason: str = ""
    # Scope bound to the family at issuance; preserved across rotations.
    scopes: frozenset[str] = frozenset()
    # Ordered list of refresh token ids in the family, newest last.
    lineage: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Principal:
    """Authenticated identity produced by a successful credential check."""

    subject: str
    scopes: frozenset[str]
    kind: CredentialKind
    credential_id: str
    family_id: str | None = None
    # True only for legacy static credentials during the migration window.
    is_legacy: bool = False
