"""Shared pytest fixtures with a deterministic clock and local store."""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from auth_gateway.app import create_app
from auth_gateway.audit import Auditor
from auth_gateway.clock import FixedClock
from auth_gateway.config import Settings
from auth_gateway.storage import InMemoryStore

# A fixed legacy static credential used across tests.
LEGACY_KEY = "LEGACY-STATIC-KEY-001"


@pytest.fixture
def clock() -> FixedClock:
    # Migration window starts open and closes at t=2000.
    return FixedClock(1000.0)


@pytest.fixture
def settings() -> Settings:
    return Settings(
        access_token_ttl=60,
        refresh_token_ttl=100,
        default_api_key_ttl=1000,
        rate_limit_per_window=3,
        rate_limit_window_seconds=60,
        migration_window_ends_at=2000,
        legacy_scope=frozenset({"read:public"}),
    )


@pytest.fixture
def auditor() -> Auditor:
    return Auditor()


@pytest.fixture
def store() -> InMemoryStore:
    return InMemoryStore()


@pytest.fixture
def app(settings, clock, auditor, store):
    return create_app(
        settings,
        legacy_keys={LEGACY_KEY},
        auditor=auditor,
        clock=clock,
        store=store,
    )


@pytest.fixture
def client(app):
    # raise_server_exceptions lets us observe real 500 mapping if broken.
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture(autouse=True)
def _log_test_inputs(request, caplog):
    """Log each test's inputs/decisions (caplog captures audit records)."""
    caplog.set_level(logging.INFO, logger="auth_gateway.audit")
    yield


def issue_api_key(client, scopes, ttl=None, subject="api"):
    payload = {"scopes": list(scopes), "subject": subject}
    if ttl is not None:
        payload["ttl"] = ttl
    resp = client.post("/auth/api-keys", json=payload)
    assert resp.status_code == 200, resp.text
    return resp.json()


def issue_tokens(client, scopes, subject="user"):
    resp = client.post("/auth/tokens", json={"scopes": list(scopes), "subject": subject})
    assert resp.status_code == 200, resp.text
    return resp.json()
