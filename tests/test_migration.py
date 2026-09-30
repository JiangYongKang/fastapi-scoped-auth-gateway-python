"""Legacy credential migration: in-window vs post-window behavior."""

from __future__ import annotations

import logging

import pytest

log = logging.getLogger("tests.migration")

pytestmark = pytest.mark.asyncio

LEGACY_HEADER = "legacy-static-key:legacy-static-secret"


async def test_legacy_credential_works_with_low_scopes_during_window(client):
    r = await client.get("/public", headers={"X-Legacy-Credential": LEGACY_HEADER})
    log.info("in-window input=legacy required=read:public decision=%s marker=%s",
             r.status_code, r.headers.get("X-Auth-Legacy"))
    assert r.status_code == 200
    assert r.headers.get("X-Auth-Legacy") == "true"

    # Low-privilege: it must not reach a higher-scoped endpoint.
    r2 = await client.get("/items", headers={"X-Legacy-Credential": LEGACY_HEADER})
    assert r2.status_code == 403
    assert r2.json()["error"]["code"] == "insufficient_scope"

    # And the request was counted as legacy usage for observability.
    metrics = (await client.get("/internal/metrics")).json()
    assert metrics["legacy_credential"]["accepted"] >= 1
    assert metrics["legacy_credential"]["last_accepted_identity"] == "legacy-static-key"


async def test_legacy_credential_dead_after_window(closed_client):
    """Same credential, window closed: deterministically rejected with a
    distinct reason, and no legacy marker is emitted."""
    r = await closed_client.get("/public", headers={"X-Legacy-Credential": LEGACY_HEADER})
    log.info("post-window input=legacy decision=%s %s",
             r.status_code, r.json()["error"]["code"])
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "legacy_disabled"
    assert r.headers.get("X-Auth-Legacy") is None

    metrics = (await closed_client.get("/internal/metrics")).json()
    assert metrics["legacy_credential"]["rejected_expired_window"] >= 1


async def test_legacy_decision_is_stable_across_repeated_requests(closed_client):
    """No flip-flopping: repeated calls after the window all fail."""
    for i in range(5):
        r = await closed_client.get("/public", headers={"X-Legacy-Credential": LEGACY_HEADER})
        assert r.status_code == 401, (i, r.status_code)


async def test_bad_legacy_secret_rejected_without_revealing_id(client):
    r = await client.get("/public", headers={"X-Legacy-Credential": "legacy-static-key:wrong"})
    assert r.json()["error"]["code"] == "invalid_credential"
    r2 = await client.get("/public", headers={"X-Legacy-Credential": "unknown-id:whatever"})
    assert r2.json()["error"]["code"] == "invalid_credential"


async def test_primary_credentials_unaffected_by_window_closure(closed_client):
    resp = await closed_client.post("/auth/api-keys", json={"scopes": ["read:items"]})
    key = resp.json()["api_key"]
    r = await closed_client.get("/items", headers={"X-API-Key": key})
    assert r.status_code == 200
