"""Legacy static credential migration support.

Legacy credentials are static ``identifier:secret`` pairs. While the
migration window is open they resolve to *low-privilege* principals carrying
only :attr:`Settings.legacy_scopes`, and every successful resolution is
flagged via :class:`MigrationMetrics` so the transition is observable.
Once the window closes the same credential deterministically fails -- the
decision is a pure function of the clock, so it cannot flip-flop.
"""

from __future__ import annotations

import threading

from app.config import Settings
from app.errors import AuthError, DenyReason
from app.models import LegacyCredential
from app.security import constant_time_equals


class MigrationMetrics:
    """Thread-safe counters/observability for legacy credential usage."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.accepted = 0
        self.rejected_expired_window = 0
        self.rejected_invalid = 0
        self.last_accepted_identity: str | None = None

    def record_accept(self, identifier: str) -> None:
        with self._lock:
            self.accepted += 1
            self.last_accepted_identity = identifier

    def record_window_expired(self) -> None:
        with self._lock:
            self.rejected_expired_window += 1

    def record_invalid(self) -> None:
        with self._lock:
            self.rejected_invalid += 1

    def snapshot(self) -> dict[str, int | str | None]:
        with self._lock:
            return {
                "accepted": self.accepted,
                "rejected_expired_window": self.rejected_expired_window,
                "rejected_invalid": self.rejected_invalid,
                "last_accepted_identity": self.last_accepted_identity,
            }


def resolve_legacy_credential(
    raw: str,
    settings: Settings,
    now_ts: float,
    metrics: MigrationMetrics | None = None,
) -> LegacyCredential:
    """Validate a ``identifier:secret`` legacy credential.

    Raises :class:`AuthError` with a distinguishable reason:
    ``LEGACY_DISABLED`` when the migration window is closed,
    ``INVALID_CREDENTIAL`` for malformed/unknown/wrong credentials.
    """
    if ":" not in raw:
        if metrics is not None:
            metrics.record_invalid()
        raise AuthError(DenyReason.INVALID_CREDENTIAL, "malformed legacy credential")

    identifier, _, presented_secret = raw.partition(":")
    expected_secret = settings.legacy_credentials.get(identifier)

    # Uniform response whether the identifier is unknown or the secret is
    # wrong; do not reveal which static credentials exist.
    if expected_secret is None or not constant_time_equals(
        presented_secret, expected_secret
    ):
        if metrics is not None:
            metrics.record_invalid()
        raise AuthError(DenyReason.INVALID_CREDENTIAL, "invalid legacy credential")

    if not settings.legacy_active(now_ts):
        if metrics is not None:
            metrics.record_window_expired()
        raise AuthError(
            DenyReason.LEGACY_DISABLED,
            "migration window closed; legacy credential no longer accepted",
            legacy=True,
        )

    if metrics is not None:
        metrics.record_accept(identifier)
    return LegacyCredential(identifier=identifier, scopes=settings.legacy_scopes)
