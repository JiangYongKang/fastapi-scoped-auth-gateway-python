"""Per-credential sliding-window rate limiter."""

from __future__ import annotations

from datetime import timezone

from app.config import Settings
from app.storage import CredentialStore


def utcnow_ts() -> float:
    from datetime import datetime

    return datetime.now(timezone.utc).timestamp()


class RateLimiter:
    def __init__(self, store: CredentialStore, settings: Settings) -> None:
        self.store = store
        self.settings = settings

    def allow(self, identity: str, now_ts: float | None = None) -> bool:
        """Return True if the request is within quota.

        On storage failure the exception is propagated to the caller, which
        converts it into a generic 500; it is never turned into an allow.
        """
        ts = utcnow_ts() if now_ts is None else now_ts
        return self.store.hit_and_check(
            identity,
            ts,
            self.settings.rate_limit_window.total_seconds(),
            self.settings.rate_limit_max_requests,
        )
