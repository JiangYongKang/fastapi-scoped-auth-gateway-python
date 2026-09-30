"""Application factory wiring all components with local storage."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from auth_gateway.audit import Auditor, AuditRecord
from auth_gateway.authorization import Authorizer
from auth_gateway.clock import Clock, SystemClock
from auth_gateway.config import Settings
from auth_gateway.errors import AuthError, DenyReason, StorageError
from auth_gateway.issuer import Issuer
from auth_gateway.migration import LegacyResolver
from auth_gateway.ratelimit import RateLimiter
from auth_gateway.routes_admin import router as admin_router
from auth_gateway.routes_gateway import router as gateway_router
from auth_gateway.service import AuthService
from auth_gateway.storage import InMemoryStore


def create_app(
    settings: Settings | None = None,
    *,
    legacy_keys: set[str] | None = None,
    auditor: Auditor | None = None,
    clock: Clock | None = None,
    store: InMemoryStore | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    clock = clock or SystemClock()
    auditor = auditor or Auditor()
    store = store or InMemoryStore()

    issuer = Issuer(store, settings, clock, auditor)
    legacy = LegacyResolver(legacy_keys or set(), settings, clock)
    limiter = RateLimiter(
        settings.rate_limit_per_window, settings.rate_limit_window_seconds
    )
    authorizer = Authorizer()
    service = AuthService(
        store, issuer, legacy, limiter, authorizer, clock, settings, auditor
    )

    app = FastAPI(title="Scoped Local Auth Gateway", version="0.1.0")
    app.state.service = service
    app.state.auditor = auditor
    app.state.settings = settings
    app.state.clock = clock
    app.state.store = store

    app.include_router(admin_router)
    app.include_router(gateway_router)

    @app.exception_handler(AuthError)
    async def _on_auth_error(request: Request, exc: AuthError) -> JSONResponse:
        # Stable machine-readable code + status; no internal detail leaks.
        return JSONResponse(
            status_code=exc.http_status,
            content={
                "error": exc.reason.value,
                "error_description": _public_description(exc.reason),
            },
            headers={"WWW-Authenticate": "Bearer"}
            if exc.http_status in (401,)
            else None,
        )

    @app.exception_handler(StorageError)
    async def _on_storage_error(
        request: Request, exc: StorageError
    ) -> JSONResponse:
        # Log the real cause server side; answer generically.
        logging.getLogger("auth_gateway").exception("storage failure")
        auditor.record(
            AuditRecord(
                event="access",
                decision="deny",
                reason=DenyReason.INTERNAL_ERROR.value,
                detail="storage failure hidden from client",
            )
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": DenyReason.INTERNAL_ERROR.value,
                "error_description": "internal error",
            },
        )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


def _public_description(reason: DenyReason) -> str:
    """Client-safe, generic descriptions (no resource/credential hints)."""
    return {
        DenyReason.MISSING_CREDENTIAL: "authentication required",
        DenyReason.INVALID_CREDENTIAL: "authentication failed",
        DenyReason.INSUFFICIENT_SCOPE: "not permitted for this resource",
        DenyReason.RATE_LIMITED: "request quota exceeded",
        DenyReason.INTERNAL_ERROR: "internal error",
        # Refresh endpoints may expose the specific rotation reasons; they
        # do not address a shared resource and the caller owns the token.
        DenyReason.EXPIRED_TOKEN: "token has expired",
        DenyReason.REVOKED_CREDENTIAL: "credential has been revoked",
        DenyReason.REFRESH_REUSE_DETECTED: "refresh token reuse detected",
        DenyReason.REFRESH_FAMILY_REVOKED: "credential family revoked",
        DenyReason.LEGACY_REVOKED_POST_WINDOW: "authentication failed",
    }.get(reason, "authentication failed")
