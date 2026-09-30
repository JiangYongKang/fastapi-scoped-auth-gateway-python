"""Refresh-token rotation, replay detection and concurrent reuse."""

from __future__ import annotations

import asyncio
import logging

import httpx
import pytest

log = logging.getLogger("tests.refresh")

pytestmark = pytest.mark.asyncio


async def _issue(client: httpx.AsyncClient, scopes=("read:items",)) -> dict:
    resp = await client.post("/auth/tokens", json={"scopes": list(scopes)})
    assert resp.status_code == 201, resp.text
    return resp.json()


async def test_refresh_rotates_and_invalidates_old_token(client):
    """Input: a valid refresh token. Basis: first redeem consumes it
    (200); second identical redeem hits REUSE_DETECTED."""
    tokens = await _issue(client)
    log.info("input refresh_token=%s", tokens["refresh_token"][:12] + "...")

    ok = await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    log.info("first refresh -> %s", ok.status_code)
    assert ok.status_code == 200
    assert ok.json()["refresh_token"] != tokens["refresh_token"]

    replay = await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    log.info("replay decision status=%s code=%s", replay.status_code, replay.json()["error"]["code"])
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "reuse_detected"


async def test_replay_burns_entire_family(client):
    """After a replay, the freshly rotated token is rejected too, and the
    rejection reason stays reuse_detected (distinct from revoked/expired)."""
    tokens = await _issue(client)
    rotated = (await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})).json()

    await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})

    follow = await client.post("/auth/refresh", json={"refresh_token": rotated["refresh_token"]})
    log.info("rotated token after burn -> %s %s", follow.status_code, follow.json()["error"]["code"])
    assert follow.status_code == 401
    assert follow.json()["error"]["code"] == "reuse_detected"


async def test_concurrent_refresh_only_one_succeeds(client):
    """N simultaneous redeems of the same token: exactly one 200, the rest
    401 reuse_detected, and the whole family is dead afterwards."""
    tokens = await _issue(client)
    payload = {"refresh_token": tokens["refresh_token"]}

    results = await asyncio.gather(
        *[client.post("/auth/refresh", json=payload) for _ in range(8)]
    )
    codes = [r.status_code for r in results]
    bodies = [r.json() for r in results]
    log.info("concurrent refresh statuses=%s", codes)
    assert codes.count(200) == 1, codes
    assert all(b["error"]["code"] == "reuse_detected" for b in bodies if "error" in b)

    # The winner's new token is unusable because the family was burned by losers.
    winner = next(r.json() for r in results if r.status_code == 200)
    after = await client.post("/auth/refresh", json={"refresh_token": winner["refresh_token"]})
    assert after.status_code == 401
    assert after.json()["error"]["code"] == "reuse_detected"


async def test_unknown_and_expired_are_distinguishable(client, monkeypatch):
    missing = await client.post("/auth/refresh", json={"refresh_token": "does-not-exist"})
    assert missing.json()["error"]["code"] == "invalid_credential"

    # Expired token: mint one then force its expiry by shifting the clock
    # through the service layer.
    service = client._transport.app.state.auth_service  # type: ignore[attr-defined]
    tokens = await _issue(client)
    from app.models import RefreshTokenRecord

    record = service.store.get_refresh_token(__import__("app.security", fromlist=["hash_token"]).hash_token(tokens["refresh_token"]))
    from datetime import datetime, timedelta, timezone

    record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    expired = await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    log.info("expired decision -> %s", expired.json()["error"]["code"])
    assert expired.json()["error"]["code"] == "expired_credential"


async def test_admin_revocation_is_distinct_from_reuse(client):
    tokens = await _issue(client)
    rotated = (await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})).json()
    family_id = client._transport.app.state.auth_service.store.get_refresh_token(  # type: ignore[attr-defined]
        __import__("app.security", fromlist=["hash_token"]).hash_token(rotated["refresh_token"])
    ).family_id

    revoked = await client.post("/auth/revoke/family", json={"family_id": family_id})
    assert revoked.status_code == 204
    resp = await client.post("/auth/refresh", json={"refresh_token": rotated["refresh_token"]})
    assert resp.json()["error"]["code"] == "revoked_credential"
