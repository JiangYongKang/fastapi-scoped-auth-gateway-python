"""Distinguishable auth/authz/rate-limit error reasons."""

from __future__ import annotations

from enum import Enum


class DenyReason(str, Enum):
    MISSING_CREDENTIAL = "missing_credential"
    INVALID_CREDENTIAL = "invalid_credential"
    EXPIRED_CREDENTIAL = "expired_credential"
    REVOKED_CREDENTIAL = "revoked_credential"
    REUSE_DETECTED = "reuse_detected"
    INSUFFICIENT_SCOPE = "insufficient_scope"
    RATE_LIMITED = "rate_limited"
    LEGACY_DISABLED = "legacy_disabled"
    INTERNAL_ERROR = "internal_error"


class AuthError(Exception):
    def __init__(self, reason: DenyReason, detail: str = "", *, legacy: bool = False) -> None:
        self.reason = reason
        self.detail = detail
        self.legacy = legacy
        super().__init__(f"{reason.value}: {detail}")
