"""Refresh token rotation: single use, replay/concurrency, family kill."""

from __future__ import annotations

import logging
import threading

from tests.conftest import issue_tokens

log = logging.getLogger("tests.refresh")


def _rotate(client, refresh_token):
    log.info("INPUT rotate refresh_token_prefix=%s", refresh_token[:12])
    resp = client.post("/auth/refresh", json={"refresh_token": refresh_token})
    log.info(
        "DECISION status=%s body=%s",
        resp.status_code,
        {k: (v[:12] + "..." if isinstance(v, str) and len(v) > 16 else v)
         for k, v in resp.json().items()} if resp.headers.get("content-type", "").startswith("application/json") else resp.text,
    )
    return resp


def test_first_refresh_succeeds_and_rotates(client):
    tokens = issue_tokens(client, ["read:profile"])
    resp = _rotate(client, tokens["refresh_token"])
    assert resp.status_code == 200
    new = resp.json()
    # Rotation: new refresh token differs, old one must not be returned.
    assert new["refresh_token"] != tokens["refresh_token"]
    assert new["access_token"] != tokens["access_token"]


def test_refresh_token_is_single_use(client):
    tokens = issue_tokens(client, ["read:profile"])
    first = _rotate(client, tokens["refresh_token"])
    assert first.status_code == 200
    # Re-presenting the same (now consumed) token is a replay.
    replay = _rotate(client, tokens["refresh_token"])
    assert replay.status_code == 401
    assert replay.json()["error"] == "refresh_reuse_detected"


def test_replay_revokes_entire_family_including_rotated_token(client):
    tokens = issue_tokens(client, ["read:profile"])
    rotated = _rotate(client, tokens["refresh_token"]).json()

    # Attacker replays the old token -> family-wide invalidation.
    replay = _rotate(client, tokens["refresh_token"])
    assert replay.json()["error"] == "refresh_reuse_detected"

    # The legitimately rotated token must now also be rejected.
    after = _rotate(client, rotated["refresh_token"])
    assert after.status_code == 401
    assert after.json()["error"] == "refresh_family_revoked"


def test_expired_refresh_token_is_distinguishable(client, clock):
    tokens = issue_tokens(client, ["read:profile"])  # issued at t=1000
    clock.advance(101)  # refresh_token_ttl = 100
    resp = _rotate(client, tokens["refresh_token"])
    assert resp.status_code == 401
    assert resp.json()["error"] == "expired_token"


def test_unknown_refresh_token_is_invalid_not_reuse(client):
    resp = _rotate(client, "rt_doesnotexist.garbage")
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_credential"


def test_concurrent_refresh_exactly_one_wins(client):
    tokens = issue_tokens(client, ["read:profile"])
    results: list[int] = []
    errors: list[str] = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        resp = client.post(
            "/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        )
        results.append(resp.status_code)
        if resp.status_code != 200:
            errors.append(resp.json()["error"])

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = [code for code in results if code == 200]
    assert len(successes) == 1, results
    # Exactly one request observes the raw reuse; once that revokes the
    # family, later in-flight requests observe the already-revoked family.
    # Either way every loser is rejected (never a 500 / never accepted).
    assert errors.count("refresh_reuse_detected") >= 1, errors
    assert set(errors) <= {
        "refresh_reuse_detected",
        "refresh_family_revoked",
    }, errors
    assert len(results) == 8

    # Family is dead afterwards: reusing the original reports family revoked.
    again = _rotate(client, tokens["refresh_token"])
    assert again.json()["error"] == "refresh_family_revoked"
