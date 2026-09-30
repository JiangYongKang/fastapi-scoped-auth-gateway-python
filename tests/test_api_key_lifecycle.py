"""API key issuance, expiry and revocation distinctions."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import pytest

log = logging.getLogger("tests.apikey")

pytestmark = pytest.mark.asyncio


async def test_api_key_revocation(client, app):
    issued = (await client.post("/auth/api-keys", json={"scopes": ["read:items"]})).json()
    headers = {"X-API-Key": issued["api_key"]}
    assert (await client.get("/items", headers=headers)).status_code == 200

    await client.post("/auth/revoke/api-key", json={"key_id": issued["key_id"]})
    r = await client.get("/items", headers=headers)
    log.info("revoked key decision=%s", r.json()["error"]["code"])
    assert r.json()["error"]["code"] == "revoked_credential"


async def test_api_key_expiry_distinct_from_revocation(client, app):
    issued = (await client.post(
        "/auth/api-keys", json={"scopes": ["read:items"], "ttl_seconds": 60}
    )).json()
    record = app.state.store.get_api_key(issued["key_id"])
    record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

    r = await client.get("/items", headers={"X-API-Key": issued["api_key"]})
    log.info("expired key decision=%s", r.json()["error"]["code"])
    assert r.json()["error"]["code"] == "expired_credential"
