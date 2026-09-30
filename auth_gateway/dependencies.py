"""FastAPI wiring: a single dependency factory per required scope."""

from __future__ import annotations

from fastapi import Request

from auth_gateway.models import Principal
from auth_gateway.service import AuthService


def get_service(request: Request) -> AuthService:
    return request.app.state.service


def _extract_credential(request: Request) -> str | None:
    """Read the presented credential from Authorization or X-API-Key.

    Supports ``Bearer <credential>`` (tokens), ``Bearer`` being absent, or a
    raw ``X-API-Key``. Returns None when nothing usable was presented.
    """
    header = request.headers.get("Authorization")
    if header:
        parts = header.split(" ", 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
        # A non-bearer Authorization value is treated as the raw key, but
        # only if it has no scheme token; otherwise it is malformed -> None.
        if len(parts) == 1:
            return header.strip()
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return api_key.strip()
    return None


def require_scope(required_scope: str):
    """Return a FastAPI dependency enforcing ``required_scope``."""

    def _dependency(request: Request) -> Principal:
        service = get_service(request)
        raw = _extract_credential(request)
        return service.authorize_request(raw, required_scope)

    return _dependency
