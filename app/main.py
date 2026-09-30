"""FastAPI application factory: wires storage, service, routes, error mapping."""

from __future__ import annotations

import logging
from collections import Counter

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.config import Settings, get_settings
from app.errors import AuthError, DenyReason
from app.migration import MigrationMetrics
from app.ratelimit import RateLimiter
from app.routes_auth import router as auth_router
from app.routes_observability import router as observability_router
from app.routes_protected import router as protected_router
from app.service import AuthService
from app.storage import InMemoryStore

# Distinguishable, stable client-facing codes. Messages stay generic so
# responses never reveal whether other credentials/resources exist.
_STATUS_BY_REASON: dict[DenyReason, int] = {
    DenyReason.MISSING_CREDENTIAL: 401,
    DenyReason.INVALID_CREDENTIAL: 401,
    DenyReason.EXPIRED_CREDENTIAL: 401,
    DenyReason.REVOKED_CREDENTIAL: 401,
    DenyReason.REUSE_DETECTED: 401,
    DenyReason.LEGACY_DISABLED: 401,
    DenyReason.INSUFFICIENT_SCOPE: 403,
    DenyReason.RATE_LIMITED: 429,
    DenyReason.INTERNAL_ERROR: 500,
}

_GENERIC_MESSAGE: dict[DenyReason, str] = {
    DenyReason.MISSING_CREDENTIAL: "authentication required",
    DenyReason.INVALID_CREDENTIAL: "authentication failed",
    DenyReason.EXPIRED_CREDENTIAL: "credential expired",
    DenyReason.REVOKED_CREDENTIAL: "credential revoked",
    DenyReason.REUSE_DETECTED: "credential reuse detected",
    DenyReason.LEGACY_DISABLED: "credential no longer accepted",
    DenyReason.INSUFFICIENT_SCOPE: "permission denied",
    DenyReason.RATE_LIMITED: "rate limit exceeded",
    DenyReason.INTERNAL_ERROR: "internal error",
}

logger = logging.getLogger("auth_gateway")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    app = FastAPI(title="Scoped Local Auth Gateway", version="0.1.0")
    store = InMemoryStore()
    limiter = RateLimiter(store, settings)
    app.state.settings = settings
    app.state.store = store
    app.state.auth_service = AuthService(store, settings, limiter)
    app.state.migration_metrics = MigrationMetrics()
    app.state.deny_counters: Counter[str] = Counter()

    app.include_router(auth_router)
    app.include_router(protected_router)
    app.include_router(observability_router)

    @app.exception_handler(AuthError)
    async def on_auth_error(request: Request, exc: AuthError) -> JSONResponse:
        app.state.deny_counters[exc.reason.value] += 1
        status = _STATUS_BY_REASON[exc.reason]
        logger.info(
            "deny path=%s reason=%s legacy=%s",
            request.url.path, exc.reason.value, exc.legacy,
        )
        return JSONResponse(
            status_code=status,
            content={
                "error": {
                    "code": exc.reason.value,
                    "message": _GENERIC_MESSAGE[exc.reason],
                }
            },
            headers={"Cache-Control": "no-store"},
        )

    @app.middleware("http")
    async def legacy_marker(request: Request, call_next):
        # Surface an explicit marker when a request was served by a legacy
        # credential, without changing the response body.
        response = await call_next(request)
        principal = getattr(request.state, "principal", None)
        if principal is not None and getattr(principal, "legacy", False):
            response.headers["X-Auth-Legacy"] = "true"
        return response

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok"}

    return app
