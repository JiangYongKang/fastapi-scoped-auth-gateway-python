"""Credential management routes (issue / refresh / revoke)."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from auth_gateway.dependencies import get_service
from auth_gateway.errors import AuthError, DenyReason
from auth_gateway.service import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])


class IssueApiKeyRequest(BaseModel):
    scopes: list[str]
    ttl: int | None = None
    subject: str = "api"


class IssueTokenRequest(BaseModel):
    scopes: list[str]
    subject: str = "user"


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/api-keys")
def issue_api_key(
    body: IssueApiKeyRequest, service: AuthService = Depends(get_service)
):
    record, raw = service.issuer.issue_api_key(
        frozenset(body.scopes), ttl=body.ttl, subject=body.subject
    )
    return {
        "api_key": raw,
        "key_id": record.key_id,
        "scopes": sorted(record.scopes),
        "expires_at": record.expires_at,
    }


@router.post("/tokens")
def issue_tokens(
    body: IssueTokenRequest, service: AuthService = Depends(get_service)
):
    return service.issuer.issue_token_family(
        frozenset(body.scopes), subject=body.subject
    )


@router.post("/refresh")
def refresh(
    body: RefreshRequest, service: AuthService = Depends(get_service)
):
    # The refresh endpoint surfaces the specific rotation reason (expired /
    # reuse / family revoked), because the caller owns the presented token.
    return service.issuer.rotate_refresh(body.refresh_token)


@router.post("/revoke/{credential_id}")
def revoke(
    credential_id: str, service: AuthService = Depends(get_service)
):
    # Accept either an API key id or a family id; revoke whichever matches.
    store = service.store
    revoked: list[str] = []
    if store.get_api_key(credential_id) is not None:
        service.issuer.revoke_api_key(credential_id)
        revoked.append("api_key")
    if store.get_family(credential_id) is not None:
        service.issuer.revoke_family(credential_id, "manual_revoke")
        revoked.append("family")
    if not revoked:
        # Do not reveal whether the id exists.
        raise AuthError(
            DenyReason.INVALID_CREDENTIAL, "no such credential", http_status=404
        )
    return {"revoked": credential_id, "types": revoked}
