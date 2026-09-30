"""Observability endpoints: migration markers and per-reason counters."""

from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter(prefix="/internal", tags=["observability"])


@router.get("/metrics")
def metrics(request: Request) -> dict:
    counters = request.app.state.deny_counters
    migration = request.app.state.migration_metrics.snapshot()
    return {
        "legacy_credential": migration,
        "denied_by_reason": dict(counters),
    }
