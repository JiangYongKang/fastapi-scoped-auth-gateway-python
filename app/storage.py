"""Local storage: protocol definition and in-memory implementation.

Everything lives behind a single lock per store, which is enough for a
single-process local deployment and makes refresh-token rotation atomic
under concurrency: exactly one of several concurrent redeem attempts for the
same refresh token can win.
"""

from __future__ import annotations

from collections import defaultdict, deque
from threading import RLock
from typing import Protocol

from app.models import (
    AccessTokenRecord,
    ApiKeyRecord,
    RefreshTokenRecord,
    TokenFamily,
)


class CredentialStore(Protocol):
    def put_api_key(self, record: ApiKeyRecord) -> None: ...
    def get_api_key(self, key_id: str) -> ApiKeyRecord | None: ...
    def revoke_api_key(self, key_id: str) -> None: ...

    def put_access_token(self, record: AccessTokenRecord) -> None: ...
    def get_access_token(self, token_hash: str) -> AccessTokenRecord | None: ...

    def put_refresh_token(self, record: RefreshTokenRecord) -> None: ...
    def get_refresh_token(self, token_hash: str) -> RefreshTokenRecord | None: ...
    def consume_refresh_token(self, token_hash: str) -> bool:
        """Atomically mark a refresh token consumed.

        Returns True exactly once; concurrent/repeated callers get False.
        """
        ...

    def create_family(self, family: TokenFamily) -> None: ...
    def get_family(self, family_id: str) -> TokenFamily | None: ...
    def revoke_family(self, family_id: str, reason: str = "admin") -> None: ...

    def hit_and_check(
        self, identity: str, now_ts: float, window: float, limit: int
    ) -> bool:
        """Record a hit and report whether ``identity`` is within ``limit``.

        Denied hits (when False is returned) are not retained, so rejected
        requests never consume quota.
        """
        ...

    def reset(self) -> None: ...


class InMemoryStore:
    def __init__(self) -> None:
        self._lock = RLock()
        self._api_keys: dict[str, ApiKeyRecord] = {}
        self._access_tokens: dict[str, AccessTokenRecord] = {}
        self._refresh_tokens: dict[str, RefreshTokenRecord] = {}
        self._families: dict[str, TokenFamily] = {}
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def put_api_key(self, record: ApiKeyRecord) -> None:
        with self._lock:
            self._api_keys[record.key_id] = record

    def get_api_key(self, key_id: str) -> ApiKeyRecord | None:
        with self._lock:
            return self._api_keys.get(key_id)

    def revoke_api_key(self, key_id: str) -> None:
        with self._lock:
            record = self._api_keys.get(key_id)
            if record is not None:
                record.revoked = True

    def put_access_token(self, record: AccessTokenRecord) -> None:
        with self._lock:
            self._access_tokens[record.token_hash] = record

    def get_access_token(self, token_hash: str) -> AccessTokenRecord | None:
        with self._lock:
            return self._access_tokens.get(token_hash)

    def put_refresh_token(self, record: RefreshTokenRecord) -> None:
        with self._lock:
            self._refresh_tokens[record.token_hash] = record

    def get_refresh_token(self, token_hash: str) -> RefreshTokenRecord | None:
        with self._lock:
            return self._refresh_tokens.get(token_hash)

    def consume_refresh_token(self, token_hash: str) -> bool:
        with self._lock:
            record = self._refresh_tokens.get(token_hash)
            if record is None or record.consumed:
                return False
            record.consumed = True
            return True

    def create_family(self, family: TokenFamily) -> None:
        with self._lock:
            self._families[family.family_id] = family

    def get_family(self, family_id: str) -> TokenFamily | None:
        with self._lock:
            return self._families.get(family_id)

    def revoke_family(self, family_id: str, reason: str = "admin") -> None:
        with self._lock:
            family = self._families.get(family_id)
            if family is not None:
                family.revoked = True
                family.revoke_reason = reason
            for token in self._refresh_tokens.values():
                if token.family_id == family_id:
                    token.revoked = True
            for token in self._access_tokens.values():
                if token.family_id == family_id:
                    token.revoked = True

    def hit_and_check(
        self, identity: str, now_ts: float, window: float, limit: int
    ) -> bool:
        with self._lock:
            bucket = self._hits[identity]
            cutoff = now_ts - window
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(now_ts)
            return True

    def reset(self) -> None:
        with self._lock:
            self._api_keys.clear()
            self._access_tokens.clear()
            self._refresh_tokens.clear()
            self._families.clear()
            self._hits.clear()
