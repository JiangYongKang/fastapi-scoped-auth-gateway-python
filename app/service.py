"""Credential lifecycle and the authenticate -> authorize -> rate-limit chain.

Layers (each decision raises a distinguishable :class:`AuthError`):

1. authenticate  -- turn a presented credential into a :class:`Principal`
2. authorize     -- default-deny scope check against the required scopes
3. rate-limit    -- per-credential quota *after* authz, so denials are free

Refresh-token rotation is reuse-detecting: redeeming a token that was already
consumed revokes the whole family, and every later member of that family is
rejected with ``REUSE_DETECTED``.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from app.config import Settings
from app.errors import AuthError, DenyReason
from app.models import (
    AccessTokenRecord,
    ApiKeyRecord,
    Principal,
    RefreshTokenRecord,
    TokenFamily,
)
from app.ratelimit import RateLimiter
from app.security import (
    generate_secret,
    hash_secret,
    hash_token,
    verify_secret,
)
from app.storage import CredentialStore

logger = logging.getLogger("auth_gateway.service")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuthService:
    def __init__(
        self, store: CredentialStore, settings: Settings, rate_limiter: RateLimiter
    ) -> None:
        self.store = store
        self.settings = settings
        self.rate_limiter = rate_limiter

    # ------------------------------------------------------------------ issue

    def issue_api_key(
        self, scopes: frozenset[str], ttl: timedelta | None | str = "default"
    ) -> dict:
        scopes = frozenset(scopes)
        if not scopes:
            # A credential with no scopes could never pass default-deny.
            raise AuthError(DenyReason.INSUFFICIENT_SCOPE, "scopes must not be empty")
        key_id = generate_secret(12)
        secret = generate_secret(32)
        now = utcnow()
        if ttl == "default":
            ttl = self.settings.api_key_default_ttl
        expires_at = now + ttl if ttl is not None else None
        self.store.put_api_key(
            ApiKeyRecord(
                key_id=key_id,
                secret_hash=hash_secret(secret),
                scopes=scopes,
                issued_at=now,
                expires_at=expires_at,
            )
        )
        logger.info("issued api key key_id=%s scopes=%s", key_id, sorted(scopes))
        return {
            "api_key": f"{key_id}.{secret}",
            "key_id": key_id,
            "scopes": sorted(scopes),
            "expires_at": expires_at.isoformat() if expires_at else None,
        }

    def _mint_token_pair(
        self, family_id: str, scopes: frozenset[str], now: datetime
    ) -> dict:
        access = generate_secret(32)
        refresh = generate_secret(32)
        self.store.put_access_token(
            AccessTokenRecord(
                token_hash=hash_token(access),
                family_id=family_id,
                scopes=scopes,
                issued_at=now,
                expires_at=now + self.settings.access_token_ttl,
            )
        )
        self.store.put_refresh_token(
            RefreshTokenRecord(
                token_hash=hash_token(refresh),
                family_id=family_id,
                scopes=scopes,
                issued_at=now,
                expires_at=now + self.settings.refresh_token_ttl,
            )
        )
        family = self.store.get_family(family_id)
        if family is not None:
            family.lineage.append(hash_token(refresh))
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "Bearer",
            "expires_in": int(self.settings.access_token_ttl.total_seconds()),
            "scopes": sorted(scopes),
        }

    def issue_tokens(self, scopes: frozenset[str]) -> dict:
        scopes = frozenset(scopes)
        if not scopes:
            raise AuthError(DenyReason.INSUFFICIENT_SCOPE, "scopes must not be empty")
        family_id = generate_secret(16)
        self.store.create_family(TokenFamily(family_id=family_id))
        return self._mint_token_pair(family_id, scopes, utcnow())

    # ---------------------------------------------------------------- refresh

    def refresh(self, refresh_token: str) -> dict:
        """Rotate a refresh token.

        Order of checks distinguishes the failure reasons:
        unknown/malformed -> INVALID; expired -> EXPIRED; family dead -> the
        family's death cause (REUSE_DETECTED vs REVOKED); already consumed ->
        REUSE_DETECTED *and* the family is burned.
        """
        now = utcnow()
        token_hash = hash_token(refresh_token)
        record = self.store.get_refresh_token(token_hash)
        if record is None:
            logger.info("refresh rejected reason=invalid_credential (unknown token)")
            raise AuthError(
                DenyReason.INVALID_CREDENTIAL, "unknown refresh token"
            )

        if record.expires_at <= now:
            logger.info(
                "refresh rejected reason=expired_credential family=%s",
                record.family_id,
            )
            raise AuthError(
                DenyReason.EXPIRED_CREDENTIAL, "refresh token expired"
            )

        family = self.store.get_family(record.family_id)
        if family is not None and family.revoked:
            reason = (
                DenyReason.REUSE_DETECTED
                if family.revoke_reason == "reuse"
                else DenyReason.REVOKED_CREDENTIAL
            )
            logger.info(
                "refresh rejected reason=%s family=%s",
                reason.value, family.family_id,
            )
            raise AuthError(reason, f"family revoked ({family.revoke_reason})")

        # Atomic compare-and-consume: exactly one concurrent caller wins.
        if not self.store.consume_refresh_token(token_hash):
            logger.warning(
                "refresh replay detected family=%s; revoking whole family",
                record.family_id,
            )
            self.store.revoke_family(record.family_id, reason="reuse")
            raise AuthError(
                DenyReason.REUSE_DETECTED,
                "refresh token was already used; credential family revoked",
            )

        pair = self._mint_token_pair(record.family_id, record.scopes, now)
        logger.info(
            "refresh rotated family=%s scopes=%s",
            record.family_id, sorted(record.scopes),
        )
        return pair

    # ---------------------------------------------------------------- revoke

    def revoke_api_key(self, key_id: str) -> None:
        self.store.revoke_api_key(key_id)
        logger.info("api key revoked key_id=%s", key_id)

    def revoke_family(self, family_id: str) -> None:
        self.store.revoke_family(family_id, reason="admin")
        logger.info("token family revoked family=%s", family_id)

    # ----------------------------------------------------------- authenticate

    def authenticate_api_key(self, presented: str) -> Principal:
        key_id, sep, secret = presented.partition(".")
        if not sep or not key_id or not secret:
            raise AuthError(DenyReason.INVALID_CREDENTIAL, "malformed api key")
        record = self.store.get_api_key(key_id)
        # Verify even when the record is missing? We cannot (no salt). The
        # key id itself is high entropy, so its absence reveals nothing else.
        if record is None or not verify_secret(secret, record.secret_hash):
            raise AuthError(DenyReason.INVALID_CREDENTIAL, "invalid api key")
        if record.revoked:
            raise AuthError(DenyReason.REVOKED_CREDENTIAL, "api key revoked")
        if record.expires_at is not None and record.expires_at <= utcnow():
            raise AuthError(DenyReason.EXPIRED_CREDENTIAL, "api key expired")
        return Principal(
            identity=f"apikey:{record.key_id}", scopes=record.scopes
        )

    def authenticate_access_token(self, token: str) -> Principal:
        record = self.store.get_access_token(hash_token(token))
        if record is None:
            raise AuthError(DenyReason.INVALID_CREDENTIAL, "unknown access token")
        if record.revoked:
            # Access tokens are only revoked via family burn.
            raise AuthError(DenyReason.REUSE_DETECTED, "credential family burned")
        if record.expires_at <= utcnow():
            raise AuthError(DenyReason.EXPIRED_CREDENTIAL, "access token expired")
        return Principal(
            identity=f"family:{record.family_id}", scopes=record.scopes
        )

    # ------------------------------------------------------- authorize + qos

    def authorize(self, principal: Principal, required: frozenset[str]) -> None:
        """Default-deny: every required scope must be present.

        Empty requirements still require an authenticated principal; a
        credential carrying no scopes is rejected.
        """
        missing = required - principal.scopes
        if required and missing or (not required and not principal.scopes):
            logger.info(
                "denied identity=%s required=%s granted=%s reason=insufficient_scope",
                principal.identity, sorted(required), sorted(principal.scopes),
            )
            raise AuthError(
                DenyReason.INSUFFICIENT_SCOPE,
                f"missing scopes: {sorted(missing)}",
                legacy=principal.legacy,
            )

    def enforce(
        self,
        principal: Principal,
        required: frozenset[str],
        now_ts: float | None = None,
    ) -> None:
        """Full decision chain for a request: authorize then rate-limit."""
        self.authorize(principal, required)
        if not self.rate_limiter.allow(principal.identity, now_ts=now_ts):
            logger.info(
                "denied identity=%s reason=rate_limited", principal.identity
            )
            raise AuthError(
                DenyReason.RATE_LIMITED, "credential rate limit exceeded"
            )
