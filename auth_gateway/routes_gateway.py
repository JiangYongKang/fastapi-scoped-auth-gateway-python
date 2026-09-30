"""Protected resource routes demonstrating the auth chain."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from auth_gateway.dependencies import require_scope
from auth_gateway.models import Principal

router = APIRouter(tags=["resources"])


@router.get("/public")
def read_public(
    principal: Principal = Depends(require_scope("read:public")),
):
    return {
        "resource": "public",
        "subject": principal.subject,
        "legacy": principal.is_legacy,
        "scopes": sorted(principal.scopes),
    }


@router.get("/profile")
def read_profile(
    principal: Principal = Depends(require_scope("read:profile")),
):
    return {
        "resource": "profile",
        "subject": principal.subject,
        "scopes": sorted(principal.scopes),
    }


@router.post("/admin/tasks")
def run_admin_task(
    principal: Principal = Depends(require_scope("admin:tasks")),
):
    return {"resource": "admin", "subject": principal.subject, "ran": True}
