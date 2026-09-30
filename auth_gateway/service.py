"""The auth chain: authenticate -> authorize -> rate-limit, in one place.

Routes stay thin; this module owns the ordered decision chain and the
mapping of every failure to a distinguishable :class:`DenyReason`.
Denied requests (missing/invalid/insufficient scope) never consume rate
limit quota; storage failures are surfaced as generic internal errors.
"""

from __future__ import annotations

from auth_gateway.audit import Auditor, AuditRecord
from auth_gateway.authorization import Authorizer
from auth_gateway.clock import Clock
from auth_gateway.config import Settings
from auth_gateway.crypto import parse_credential, verify_secret
from auth_gateway.errors import AuthError, DenyReason, StorageError
from auth_gateway.issuer import Issuer
from auth_gateway.migration import (
    LEGACY_MARKER,
    LEGACY_WINDOW_CLOSED,
    LegacyResolver,
)
from auth_gateway.models import CredentialKind, Principal
from auth_gateway.ratelimit import RateLimiter
from auth_gateway.storage import CredentialStore


class AuthService:
    def __init__(
        self,
        store: CredentialStore,
        issuer: Issuer,
        legacy: LegacyResolver,
        limiter: RateLimiter,
        authorizer: Authorizer,
        clock: Clock,
        settings: Settings,
        auditor: Auditor,
    ) -> None:
        self.store = store
        self.issuer = issuer
        self.legacy = legacy
        self.limiter = limiter
        self.authorizer = authorizer
        self.clock = clock
        self.settings = settings
        self.auditor = auditor

    # ---- presentation -------------------------------------------------
    def authenticate(self, raw_credential: str | None) -> Principal:
        """Validate presentation and lifecycle; deny by default.

        Raises AuthError with a specific reason. Never discloses whether the
        failure was an unknown id, a bad secret, or a closed window: all map
        to INVALID_CREDENTIAL at the resource edge.
        """
        if raw_credential is None or raw_credential == "":
            self._deny(DenyReason.MISSING_CREDENTIAL, "no credential presented")

        assert raw_credential is not None

        # 1) Legacy static credentials take the migration path. They never
        #    match the new ``prefix_id.secret`` format.
        is_legacy, marker = self.legacy.resolve(raw_credential)
        if is_legacy:
            return self._authenticate_legacy(raw_credential, marker)

        # 2) New-format credentials: identify kind by prefix, then verify.
        try:
            token_id, secret = parse_credential(raw_credential)
        except ValueError:
            self._deny(
                DenyReason.INVALID_CREDENTIAL,
                "unrecognized credential format",
            )
            raise  # unreachable

        prefix = token_id.split("_", 1)[0]
        try:
            if prefix == "ak":
                return self._authenticate_api_key(token_id, secret)
            if prefix == "at":
                return self._authenticate_access_token(token_id, secret)
            # Unknown prefix: not a refresh token at the resource edge.
            self._deny(DenyReason.INVALID_CREDENTIAL, "unknown credential type")
        except StorageError:
            self._deny(DenyReason.INTERNAL_ERROR, "storage unavailable", 500)
        raise AuthError(DenyReason.INVALID_CREDENTIAL, "unreachable", 401)

    def _authenticate_legacy(
        self, raw: str, marker: str | None
    ) -> Principal:
        if marker == LEGACY_WINDOW_CLOSED:
            # Deterministic post-window rejection. Same credential cannot
            # pass later: the window only moves in one direction.
            self._deny(
                DenyReason.INVALID_CREDENTIAL,
                "credential rejected",
                audit_kind=CredentialKind.LEGACY.value,
                audit_id=raw,
                legacy=True,
                marker=marker,
                log_reason=DenyReason.LEGACY_REVOKED_POST_WINDOW,
            )
        # Window open: low-privilege principal with an explicit marker.
        principal = Principal(
            subject=f"legacy:{raw}",
            scopes=self.settings.legacy_scope,
            kind=CredentialKind.LEGACY,
            credential_id=raw,
            is_legacy=True,
        )
        self.auditor.record(
            AuditRecord(
                event="authenticate",
                credential_kind=CredentialKind.LEGACY.value,
                credential_id=raw,
                decision="allow",
                granted_scopes=sorted(principal.scopes),
                legacy=True,
                migration_marker=marker,
            )
        )
        return principal

    def _authenticate_api_key(self, key_id: str, secret: str) -> Principal:
        record = self.store.get_api_key(key_id)
        if record is None or not verify_secret(secret, record.secret_hash):
            # Same response whether the id or the secret was wrong.
            self._deny(DenyReason.INVALID_CREDENTIAL, "invalid api key")
        assert record is not None
        now = self.clock.now()
        if record.revoked:
            self._deny_invalid(
                CredentialKind.API_KEY.value,
                key_id,
                DenyReason.REVOKED_CREDENTIAL,
                "api key revoked",
            )
        if now >= record.expires_at:
            self._deny_invalid(
                CredentialKind.API_KEY.value,
                key_id,
                DenyReason.EXPIRED_TOKEN,
                "api key expired",
            )
        return Principal(
            subject=record.key_id,
            scopes=record.scopes,
            kind=CredentialKind.API_KEY,
            credential_id=key_id,
            family_id=record.family_id,
        )

    def _authenticate_access_token(
        self, token_id: str, secret: str
    ) -> Principal:
        record = self.store.get_access_token(token_id)
        if record is None or not verify_secret(secret, record.secret_hash):
            self._deny(DenyReason.INVALID_CREDENTIAL, "invalid access token")
        assert record is not None
        now = self.clock.now()
        if record.revoked:
            self._deny_invalid(
                CredentialKind.ACCESS_TOKEN.value,
                token_id,
                DenyReason.REVOKED_CREDENTIAL,
                "access token revoked",
            )
        if now >= record.expires_at:
            self._deny_invalid(
                CredentialKind.ACCESS_TOKEN.value,
                token_id,
                DenyReason.EXPIRED_TOKEN,
                "access token expired",
            )
        return Principal(
            subject=record.family_id,
            scopes=record.scopes,
            kind=CredentialKind.ACCESS_TOKEN,
            credential_id=token_id,
            family_id=record.family_id,
        )

    # ---- full chain ---------------------------------------------------
    def authorize_request(
        self, raw_credential: str | None, required_scope: str
    ) -> Principal:
        """Authenticate -> authorize scope -> consume rate-limit quota.

        Quota is consumed only after a credential is valid and authorized,
        so every earlier failure costs the caller nothing.
        """
        principal = self.authenticate(raw_credential)

        if not self.authorizer.has_scope(principal, required_scope):
            self._deny(
                DenyReason.INSUFFICIENT_SCOPE,
                f"scope {required_scope!r} required",
                audit_kind=principal.kind.value,
                audit_id=principal.credential_id,
                required_scope=required_scope,
                granted=principal.scopes,
                legacy=principal.is_legacy,
            )

        # Scope passed: only now touch the rate limiter.
        now = self.clock.now()
        if not self.limiter.check(principal.credential_id, now):
            self._deny(
                DenyReason.RATE_LIMITED,
                "per-credential quota exceeded",
                http_status=429,
                audit_kind=principal.kind.value,
                audit_id=principal.credential_id,
                required_scope=required_scope,
                granted=principal.scopes,
                legacy=principal.is_legacy,
            )
        remaining = self.limiter.consume(principal.credential_id, now)

        self.auditor.record(
            AuditRecord(
                event="access",
                credential_kind=principal.kind.value,
                credential_id=principal.credential_id,
                required_scope=required_scope,
                granted_scopes=sorted(principal.scopes),
                decision="allow",
                legacy=principal.is_legacy,
                migration_marker=(
                    LEGACY_MARKER if principal.is_legacy else None
                ),
                rate_limit_remaining=remaining,
            )
        )
        return principal

    # ---- deny helper --------------------------------------------------
    def _deny_invalid(
        self,
        audit_kind: str,
        audit_id: str,
        true_reason: DenyReason,
        detail: str,
    ) -> None:
        """Log the true lifecycle reason but answer uniformly as invalid.

        This prevents a caller from distinguishing 'revoked' vs 'expired'
        vs 'never existed' for a credential they do not own.
        """
        self._deny(
            DenyReason.INVALID_CREDENTIAL,
            "credential rejected",
            audit_kind=audit_kind,
            audit_id=audit_id,
            log_reason=true_reason,
        )

    def _deny(
        self,
        reason: DenyReason,
        detail: str,
        http_status: int = 401,
        *,
        audit_kind: str | None = None,
        audit_id: str | None = None,
        required_scope: str | None = None,
        granted: frozenset[str] | None = None,
        legacy: bool = False,
        marker: str | None = None,
        log_reason: DenyReason | None = None,
    ) -> None:
        self.auditor.record(
            AuditRecord(
                event="access",
                credential_kind=audit_kind,
                credential_id=audit_id,
                required_scope=required_scope,
                granted_scopes=sorted(granted or frozenset()),
                decision="deny",
                # The true internal reason is logged for observability...
                reason=(log_reason or reason).value,
                legacy=legacy,
                migration_marker=marker,
                detail=detail,
            )
        )
        # ...but the client only sees the edge-safe reason/status.
        raise AuthError(reason, detail, http_status=http_status)
