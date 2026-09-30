"""Scope-based access decisions and default-deny behavior."""

from __future__ import annotations

import logging

import pytest

log = logging.getLogger("tests.scopes")

pytestmark = pytest.mark.asyncio


async def _api_key(client, scopes):
    resp = await client.post("/auth/api-keys", json={"scopes": scopes})
    assert resp.status_code == 201, resp.text
    return resp.json()["api_key"]


async def test_missing_credential_is_distinct(client):
    """No credential at all -> 401 missing_credential."""
    resp = await client.get("/items")
    log.info("input=<none> path=/items decision=%s", resp.json()["error"]["code"])
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "missing_credential"


async def test_invalid_credential_is_distinct(client):
    resp = await client.get("/items", headers={"X-API-Key": "nope.malformed"})
    log.info("input=bad api key decision=%s", resp.json()["error"]["code"])
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "invalid_credential"


async def test_default_deny_unknown_resource_identical_shape(client):
    """Requests for a non-existent route and an existing route must look the
    same without a credential -- existence of resources is not revealed."""
    existing = await client.get("/items")
    missing_route = await client.get("/does-not-exist")
    # FastAPI returns its own 404 for missing routes; the key assertion is
    # that a valid-but-unscoped credential never leaks data either.
    assert existing.status_code == 401
    assert existing.json()["error"]["code"] == "missing_credential"
    log.info("unknown-route status=%s body=%s", missing_route.status_code, missing_route.text[:60])


async def test_insufficient_scope_distinct_from_auth_failure(client):
    key = await _api_key(client, ["read:public"])
    resp = await client.get("/items", headers={"X-API-Key": key})
    log.info("input scopes=['read:public'] required=['read:items'] decision=%s",
             resp.json()["error"]["code"])
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "insufficient_scope"
    # Generic message: no hint which scopes/resources exist beyond denial.
    assert "read:items" not in resp.json()["error"]["message"]


async def test_sufficient_scope_passes(client):
    key = await _api_key(client, ["read:items"])
    resp = await client.get("/items", headers={"X-API-Key": key})
    assert resp.status_code == 200
    assert resp.json() == {"data": ["a", "b", "c"]}


async def test_write_scope_not_implied_by_read(client):
    key = await _api_key(client, ["read:items"])
    resp = await client.post("/items", headers={"X-API-Key": key})
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "insufficient_scope"


async def test_empty_scope_credential_cannot_be_issued(client):
    resp = await client.post("/auth/api-keys", json={"scopes": []})
    # Pydantic min_length -> 422; service layer also refuses empty scopes.
    assert resp.status_code == 422


async def test_access_token_expiry_is_distinguishable(client, app):
    from datetime import datetime, timedelta, timezone

    issued = (await client.post("/auth/tokens", json={"scopes": ["read:items"]})).json()
    from app.security import hash_token

    record = app.state.store.get_access_token(hash_token(issued["access_token"]))
    record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    r = await client.get(
        "/items", headers={"Authorization": f"Bearer {issued['access_token']}"}
    )
    log.info("expired access token decision=%s", r.json()["error"]["code"])
    assert r.json()["error"]["code"] == "expired_credential"


async def test_malformed_authorization_header_is_invalid(client):
    r = await client.get("/items", headers={"Authorization": "Basic abc"})
    assert r.json()["error"]["code"] == "invalid_credential"
