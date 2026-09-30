"""Shared fixtures and logging of inputs + decision basis."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import pytest
from dataclasses import replace

from app.config import Settings
from app.main import create_app


@pytest.fixture
def settings() -> Settings:
    return Settings(
        rate_limit_max_requests=3,
        legacy_credentials={"legacy-static-key": "legacy-static-secret"},
        migration_enabled=True,
        migration_ends_at=None,
    )


@pytest.fixture
def expired_window_settings(settings: Settings) -> Settings:
    # Migration window closed in the past.
    return replace(settings, migration_ends_at=1.0)


@pytest.fixture
def app(settings: Settings):
    return create_app(settings=settings)


@pytest.fixture
def closed_app(expired_window_settings: Settings):
    return create_app(settings=expired_window_settings)


@pytest.fixture
async def client(app):
    import httpx

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gw"
    ) as ac:
        yield ac


@pytest.fixture
async def closed_client(closed_app):
    import httpx

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=closed_app), base_url="http://gw"
    ) as ac:
        yield ac


@pytest.fixture(autouse=True)
def _log_test_inputs(request):
    """Print the test inputs at the start of each test for traceability."""
    logging.getLogger("tests").info("START %s", request.node.nodeid)
    yield
    logging.getLogger("tests").info("END   %s", request.node.nodeid)


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()
