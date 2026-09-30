"""Auth management endpoints: issuance, refresh rotation, revocation."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.dependencies import get_service
from app.errors import AuthError, DenyReason
from app.service import AuthService

logger = logging.getLogger("auth_gateway.routes.auth")

router = APIRouter(prefix="/auth", tags=["auth"])


class IssueApiKeyRequest(BaseModel):
    scopes: list[str] = Field(min_length=1)
    ttl_seconds: float | None = Field(default=None, gt=0)


class IssueTokensRequest(BaseModel):
    scopes: list[str] = Field(min_length=1)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


class RevokeApiKeyRequest(BaseModel):
    key_id: str = Field(min_length=1)


class RevokeFamilyRequest(BaseModel):
    family_id: str = Field(min_length=1)


@router.post("/api-keys", status_code=201)
def issue_api_key(
    body: IssueApiKeyRequest,
    service: AuthService = Depends(get_service),
) -> dict:
    from datetime import timedelta

    ttl = timedelta(seconds=body.ttl_seconds) if body.ttl_seconds else "default"
    try:
        return service.issue_api_key(frozenset(body.scopes), ttl=ttl)
    except AuthError:
        raise
    except Exception:
        logger.exception("backend failure while issuing api key")
        raise AuthError(DenyReason.INTERNAL_ERROR, "issuance unavailable")


@router.post("/tokens", status_code=201)
def issue_tokens(
    body: IssueTokensRequest,
    service: AuthService = Depends(get_service),
) -> dict:
    try:
        return service.issue_tokens(frozenset(body.scopes))
    except AuthError:
        raise
    except Exception:
        logger.exception("backend failure while issuing tokens")
        raise AuthError(DenyReason.INTERNAL_ERROR, "issuance unavailable")


@router.post("/refresh")
def refresh(
    body: RefreshRequest,
    service: AuthService = Depends(get_service),
) -> dict:
    logger.info("refresh request received")
    try:
        return service.refresh(body.refresh_token)
    except AuthError:
        raise
    except Exception:
        logger.exception("backend failure during refresh")
        raise AuthError(DenyReason.INTERNAL_ERROR, "refresh unavailable")


@router.post("/revoke/api-key", status_code=204)
def revoke_api_key(
    body: RevokeApiKeyRequest,
    service: AuthService = Depends(get_service),
) -> None:
    service.revoke_api_key(body.key_id)


@router.post("/revoke/family", status_code=204)
def revoke_family(
    body: RevokeFamilyRequest,
    service: AuthService = Depends(get_service),
) -> None:
    service.revoke_family(body.family_id)
