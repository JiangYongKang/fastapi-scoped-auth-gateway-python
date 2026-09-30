"""Distinguishable authentication / authorization failure reasons.

Every deny decision in the gateway maps to exactly one ``DenyReason``.
The reason is both logged (full detail, server side) and rendered to the
client as a stable error code, while unrelated resources or credentials
must never be disclosed by the response.
"""

from __future__ import annotations

from enum import Enum


class DenyReason(str, Enum):
    # Credential lifecycle / presentation
    MISSING_CREDENTIAL = "missing_credential"
    INVALID_CREDENTIAL = "invalid_credential"
    EXPIRED_TOKEN = "expired_token"
    REVOKED_CREDENTIAL = "revoked_credential"

    # Refresh-token rotation family controls
    REFRESH_REUSE_DETECTED = "refresh_reuse_detected"
    REFRESH_FAMILY_REVOKED = "refresh_family_revoked"

    # Authorization / quota
    INSUFFICIENT_SCOPE = "insufficient_scope"
    RATE_LIMITED = "rate_limited"

    # Legacy credential migration
    LEGACY_REVOKED_POST_WINDOW = "legacy_revoked_post_window"

    # Generic internal failure (storage errors must not leak internals)
    INTERNAL_ERROR = "internal_error"


class AuthError(Exception):
    """Raised by the auth chain to signal a specific deny reason."""

    def __init__(
        self,
        reason: DenyReason,
        detail: str = "",
        *,
        http_status: int = 401,
        log_detail: str = "",
    ) -> None:
        self.reason = reason
        self.detail = detail
        self.http_status = http_status
        # Extra context intended for server-side logs only.
        self.log_detail = log_detail or detail
        super().__init__(f"{reason.value}: {detail}")


class StorageError(Exception):
    """Raised by storage backends; must be mapped to a generic 500."""
