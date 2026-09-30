"""Local credential storage.

A process-local, thread-safe in-memory implementation backed by a single
RLock. All mutation of refresh-token families goes through one atomic
operation so concurrent token exchanges cannot both succeed.
"""

from __future__ import annotations

import threading
from typing import Protocol

from auth_gateway.errors import AuthError, DenyReason, StorageError
from auth_gateway.models import (
    AccessTokenRecord,
    ApiKeyRecord,
    FamilyRecord,
    RefreshTokenRecord,
)


class CredentialStore(Protocol):
    def get_api_key(self, key_id: str) -> ApiKeyRecord | None: ...
    def put_api_key(self, record: ApiKeyRecord) -> None: ...
    def revoke_api_key(self, key_id: str) -> None: ...

    def get_refresh_token(self, token_id: str) -> RefreshTokenRecord | None: ...
    def put_refresh_token(self, record: RefreshTokenRecord) -> None: ...
    def get_family(self, family_id: str) -> FamilyRecord | None: ...
    def put_family(self, record: FamilyRecord) -> None: ...

    def get_access_token(self, token_id: str) -> AccessTokenRecord | None: ...
    def put_access_token(self, record: AccessTokenRecord) -> None: ...
    def revoke_access_token(self, token_id: str) -> None: ...

    def rotate_refresh_token(
        self, token_id: str, new_record: RefreshTokenRecord, now: float
    ) -> RefreshTokenRecord:
        """Atomically consume ``token_id`` and attach ``new_record``.

        Raises AuthError(REFRESH_REUSE_DETECTED) and revokes the family if
        ``token_id`` was already consumed. Raises if the family is revoked.
        """
        ...


class InMemoryStore:
    """Thread-safe local storage. Tests may force an injected failure."""

    def __init__(self, fail_next: bool = False) -> None:
        self._lock = threading.RLock()
        self._api_keys: dict[str, ApiKeyRecord] = {}
        self._refresh: dict[str, RefreshTokenRecord] = {}
        self._access: dict[str, AccessTokenRecord] = {}
        self._families: dict[str, FamilyRecord] = {}
        # When True, the next mutating call raises StorageError. Used to
        # prove storage failures are mapped to a generic 500.
        self._fail_next = fail_next

    def _maybe_fail(self) -> None:
        if self._fail_next:
            self._fail_next = False
            raise StorageError("injected storage failure")

    # ---- API keys -----------------------------------------------------
    def get_api_key(self, key_id: str) -> ApiKeyRecord | None:
        with self._lock:
            return self._api_keys.get(key_id)

    def put_api_key(self, record: ApiKeyRecord) -> None:
        with self._lock:
            self._maybe_fail()
            self._api_keys[record.key_id] = record

    def revoke_api_key(self, key_id: str) -> None:
        with self._lock:
            self._maybe_fail()
            record = self._api_keys.get(key_id)
            if record is not None:
                record.revoked = True

    # ---- Families -----------------------------------------------------
    def get_family(self, family_id: str) -> FamilyRecord | None:
        with self._lock:
            return self._families.get(family_id)

    def put_family(self, record: FamilyRecord) -> None:
        with self._lock:
            self._maybe_fail()
            self._families[record.family_id] = record

    def revoke_family(self, family_id: str, reason: str) -> None:
        with self._lock:
            family = self._families.get(family_id)
            if family is not None:
                family.revoked = True
                family.revoke_reason = reason
            for token in self._refresh.values():
                if token.family_id == family_id:
                    token.family_revoked = True
                    token.revoked = True

    # ---- Refresh tokens ----------------------------------------------
    def get_refresh_token(self, token_id: str) -> RefreshTokenRecord | None:
        with self._lock:
            return self._refresh.get(token_id)

    def put_refresh_token(self, record: RefreshTokenRecord) -> None:
        with self._lock:
            self._maybe_fail()
            self._refresh[record.token_id] = record

    def rotate_refresh_token(
        self, token_id: str, new_record: RefreshTokenRecord, now: float
    ) -> RefreshTokenRecord:
        """Atomically validate, consume the old token, attach the new one.

        The entire check-and-mutate sequence runs under one lock acquisition,
        so two threads presenting the same token can never both observe it as
        unconsumed. Outcomes, evaluated in order:
          * family revoked    -> REFRESH_FAMILY_REVOKED
          * already consumed  -> family revoked, REUSE_DETECTED
          * expired unconsumed-> EXPIRED_TOKEN
          * success           -> old consumed, new attached
        Reuse precedes expiry: a replayed token is an attack signal at any age.
        """
        with self._lock:
            self._maybe_fail()
            current = self._refresh.get(token_id)
            if current is None:
                raise AuthError(
                    DenyReason.INVALID_CREDENTIAL,
                    "unknown refresh token",
                    http_status=401,
                )

            family = self._families.get(current.family_id)
            if family is not None and family.revoked:
                raise AuthError(
                    DenyReason.REFRESH_FAMILY_REVOKED,
                    "credential family has been revoked",
                    http_status=401,
                    log_detail=f"family={current.family_id} "
                    f"reason={family.revoke_reason!r}",
                )
            if current.family_revoked or current.revoked:
                raise AuthError(
                    DenyReason.REFRESH_FAMILY_REVOKED,
                    "credential family has been revoked",
                    http_status=401,
                )

            if current.consumed:
                # Replay of an already rotated token: invalidate the whole
                # family, then reject with an explicit reuse reason.
                self.revoke_family(
                    current.family_id, "refresh_token_reuse_detected"
                )
                raise AuthError(
                    DenyReason.REFRESH_REUSE_DETECTED,
                    "refresh token was already used",
                    http_status=401,
                    log_detail=f"family={current.family_id} token={token_id}",
                )

            if now >= current.expires_at:
                # Natural expiry of a never-replayed token.
                raise AuthError(
                    DenyReason.EXPIRED_TOKEN,
                    "refresh token has expired",
                    http_status=401,
                    log_detail=f"now={now} expires_at={current.expires_at}",
                )

            # First (and only allowed) presentation: consume old, attach new.
            current.consumed = True
            new_record.family_id = current.family_id
            self._refresh[new_record.token_id] = new_record
            if family is not None:
                family.lineage.append(new_record.token_id)
            return current

    # ---- Access tokens ------------------------------------------------
    def get_access_token(self, token_id: str) -> AccessTokenRecord | None:
        with self._lock:
            return self._access.get(token_id)

    def put_access_token(self, record: AccessTokenRecord) -> None:
        with self._lock:
            self._maybe_fail()
            self._access[record.token_id] = record

    def revoke_access_token(self, token_id: str) -> None:
        with self._lock:
            self._maybe_fail()
            record = self._access.get(token_id)
            if record is not None:
                record.revoked = True
