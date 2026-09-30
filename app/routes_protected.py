"""Example protected resources demonstrating scope requirements."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.dependencies import require_scopes
from app.models import Principal

router = APIRouter(tags=["resources"])


@router.get("/public", dependencies=[Depends(require_scopes("read:public"))])
def read_public() -> dict:
    """Low-privilege endpoint -- reachable by legacy credentials."""
    return {"data": "public"}


@router.get("/items", dependencies=[Depends(require_scopes("read:items"))])
def read_items() -> dict:
    return {"data": ["a", "b", "c"]}


@router.post("/items", dependencies=[Depends(require_scopes("write:items"))])
def write_item() -> dict:
    return {"data": "created"}


@router.get("/me")
def who_ami(principal: Principal = Depends(require_scopes())) -> dict:
    """Any authenticated, non-empty-scoped principal can call this."""
    return {
        "identity": principal.identity,
        "scopes": sorted(principal.scopes),
        "legacy": principal.legacy,
    }
