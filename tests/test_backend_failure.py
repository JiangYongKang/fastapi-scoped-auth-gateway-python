"""Storage/backend errors must never leak internals to API responses."""

from __future__ import annotations

import logging

import pytest

log = logging.getLogger("tests.backend")

pytestmark = pytest.mark.asyncio


class ExplodingStore:
    def get_api_key(self, key_id):
        raise RuntimeError("boom: internal socket 10.0.0.1:1234")

    def get_access_token(self, token_hash):
        raise RuntimeError("boom: internal socket 10.0.0.1:1234")

    def hit_and_check(self, *a, **k):
        raise RuntimeError("boom: limiter backend down")


async def test_backend_error_on_authenticate_is_generic(app, client):
    exploding = ExplodingStore()
    app.state.auth_service.store = exploding
    app.state.auth_service.rate_limiter.store = exploding

    r = await client.get("/items", headers={"X-API-Key": "kid.sec"})
    log.info("backend-down auth decision=%s body=%s", r.status_code, r.text)
    assert r.status_code == 500
    body = r.json()["error"]
    assert body["code"] == "internal_error"
    assert "boom" not in r.text and "10.0.0.1" not in r.text


async def test_backend_error_during_rate_limit_is_generic(app, client):
    """Authenticate succeeds, then the limiter's storage blows up."""
    issued = (await client.post("/auth/api-keys", json={"scopes": ["read:items"]})).json()
    exploding = ExplodingStore()

    class HybridStore:
        def __init__(self, real, exploding):
            self.real = real
            self.exploding = exploding

        def get_api_key(self, key_id):
            return self.real.get_api_key(key_id)

        def hit_and_check(self, *a, **k):
            return self.exploding.hit_and_check(*a, **k)

    app.state.auth_service.rate_limiter.store = HybridStore(app.state.store, exploding)
    r = await client.get("/items", headers={"X-API-Key": issued["api_key"]})
    assert r.status_code == 500
    assert "boom" not in r.text
