"""Per-credential rate limiting at the quota boundary."""

from __future__ import annotations

import logging

import pytest

log = logging.getLogger("tests.ratelimit")

pytestmark = pytest.mark.asyncio


async def _api_key(client, scopes=("read:items",)):
    resp = await client.post("/auth/api-keys", json={"scopes": list(scopes)})
    return resp.json()["api_key"]


async def test_requests_at_and_over_limit(client):
    """Fixture limit is 3/window: 1..3 succeed, 4th is rate_limited."""
    key = await _api_key(client)
    headers = {"X-API-Key": key}
    for i in range(3):
        r = await client.get("/items", headers=headers)
        log.info("request %d input=valid-key decision=%s", i + 1, r.status_code)
        assert r.status_code == 200
    denied = await client.get("/items", headers=headers)
    log.info("request 4 decision=%s code=%s", denied.status_code, denied.json()["error"]["code"])
    assert denied.status_code == 429
    assert denied.json()["error"]["code"] == "rate_limited"


async def test_denied_authorizations_do_not_consume_quota(client):
    """401/403 denials happen before the limiter and must not eat quota."""
    key = await _api_key(client, scopes=["read:public"])
    for i in range(5):
        r = await client.get("/items", headers={"X-API-Key": key})
        assert r.status_code == 403  # insufficient scope, not counted
        r2 = await client.get("/items")
        assert r2.status_code == 401  # missing credential, not counted
    good = await _api_key(client)
    for i in range(3):
        assert (await client.get("/items", headers={"X-API-Key": good})).status_code == 200
    log.info("denied requests left the valid credential with full quota")


async def test_rate_limit_is_per_credential(client):
    key_a = await _api_key(client)
    key_b = await _api_key(client)
    for _ in range(3):
        assert (await client.get("/items", headers={"X-API-Key": key_a})).status_code == 200
    assert (await client.get("/items", headers={"X-API-Key": key_a})).status_code == 429
    # Other credential unaffected.
    assert (await client.get("/items", headers={"X-API-Key": key_b})).status_code == 200
