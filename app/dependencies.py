"""FastAPI dependencies: the request-side decision chain.

Chain per request:

1. extract credential  (missing -> ``MISSING_CREDENTIAL``)
2. authenticate        (invalid / expired / revoked / reuse, distinguishable)
3. legacy resolution   (only when no primary credential is presented)
4. authorize + rate-limit (see :meth:`AuthService.enforce`)

Storage failures are caught and surfaced as a generic ``INTERNAL_ERROR`` so
that backend exception text never reaches clients.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from fastapi import Depends, Request

from app.errors import AuthError, DenyReason
from app.migration import resolve_legacy_credential
from app.models import Principal
from app.ratelimit import utcnow_ts
from app.service import AuthService

logger = logging.getLogger("auth_gateway.deps")


def get_service(request: Request) -> AuthService:
    return request.app.state.auth_service


def _extract_bearer(request: Request) -> str | None:
    header = request.headers.get("Authorization", "")
    if not header:
        return None
    parts = header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise AuthError(
            DenyReason.INVALID_CREDENTIAL, "malformed Authorization header"
        )
    return parts[1].strip()


def authenticate(request: Request) -> Principal:
    """Resolve any presented credential into a :class:`Principal`."""
    service = get_service(request)
    settings = request.app.state.settings
    metrics = request.app.state.migration_metrics

    bearer = _extract_bearer(request)
    api_key = request.headers.get("X-API-Key")

    try:
        if bearer is not None:
            return service.authenticate_access_token(bearer)
        if api_key:
            return service.authenticate_api_key(api_key)

        raw_legacy = request.headers.get(settings.legacy_header_name)
        if raw_legacy:
            legacy = resolve_legacy_credential(
                raw_legacy, settings, utcnow_ts(), metrics
            )
            return Principal(
                identity=f"legacy:{legacy.identifier}",
                scopes=legacy.scopes,
                legacy=True,
            )
    except AuthError:
        raise
    except Exception:  # storage/backend failure: never leak details
        logger.exception("backend failure during authentication")
        raise AuthError(DenyReason.INTERNAL_ERROR, "authentication unavailable")

    raise AuthError(DenyReason.MISSING_CREDENTIAL, "no credential presented")


def require_scopes(*scopes: str) -> Callable[..., Principal]:
    required = frozenset(scopes)

    def dependency(
        request: Request,
        principal: Principal = Depends(authenticate),
    ) -> Principal:
        service = get_service(request)
        try:
            service.enforce(principal, required, now_ts=utcnow_ts())
            request.state.principal = principal
        except AuthError:
            raise
        except Exception:  # backend failure: never leak details
            logger.exception("backend failure during enforcement")
            raise AuthError(DenyReason.INTERNAL_ERROR, "authorization unavailable")
        # Observability marker for legacy callers that passed the chain.
        if principal.legacy:
            logger.info(
                "legacy credential accepted identity=%s scopes=%s required=%s",
                principal.identity, sorted(principal.scopes), sorted(required),
            )
        return principal

    return dependency
