"""Default-deny scope checks and per-credential rate-limit boundaries."""

from __future__ import annotations

import logging

from tests.conftest import issue_api_key, issue_tokens

log = logging.getLogger("tests.scopes")


def _get(client, path, credential=None, *, api_key=None):
    headers = {}
    if credential is not None:
        headers["Authorization"] = f"Bearer {credential}"
    if api_key is not None:
        headers["X-API-Key"] = api_key
    log.info("INPUT GET %s credential_present=%s", path, bool(headers))
    resp = client.get(path, headers=headers)
    log.info("DECISION %s status=%s error=%s", path, resp.status_code,
             resp.json().get("error") if resp.status_code != 200 else None)
    return resp


def test_missing_credential_is_distinct(client):
    resp = _get(client, "/public")
    assert resp.status_code == 401
    assert resp.json()["error"] == "missing_credential"


def test_malformed_or_unknown_credential_is_invalid(client):
    resp = _get(client, "/public", credential="not-a-real-credential")
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_credential"

    resp = _get(client, "/public", credential="ak_unknownid.deadbeef")
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_credential"


def test_default_deny_when_no_scope_bound(client):
    # A key issued with an empty scope set can access nothing.
    data = issue_api_key(client, [])
    resp = _get(client, "/public", credential=data["api_key"])
    assert resp.status_code == 401
    assert resp.json()["error"] == "insufficient_scope"


def test_insufficient_scope_is_distinct_from_invalid(client):
    data = issue_api_key(client, ["read:public"])
    # Credential is valid and authenticated, but lacks the profile scope.
    resp = _get(client, "/profile", credential=data["api_key"])
    assert resp.status_code == 401
    assert resp.json()["error"] == "insufficient_scope"
    # The same credential succeeds on the scope it does hold.
    assert _get(client, "/public", credential=data["api_key"]).status_code == 200


def test_access_token_carries_scopes(client):
    tokens = issue_tokens(client, ["read:profile"])
    ok = _get(client, "/profile", credential=tokens["access_token"])
    assert ok.status_code == 200
    denied = client.post(
        "/admin/tasks",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert denied.status_code == 401
    assert denied.json()["error"] == "insufficient_scope"


def test_rate_limit_boundary_allow_then_reject(client):
    data = issue_api_key(client, ["read:public"])  # limit = 3
    statuses = [
        _get(client, "/public", credential=data["api_key"]).status_code
        for _ in range(4)
    ]
    # First three within the fixed window succeed; the fourth is limited.
    assert statuses == [200, 200, 200, 429], statuses
    last = _get(client, "/public", credential=data["api_key"])
    assert last.status_code == 429
    assert last.json()["error"] == "rate_limited"


def test_denied_requests_do_not_consume_quota(client):
    data = issue_api_key(client, ["read:public"])  # limit = 3

    # A batch of unauthorized requests must not spend the public quota.
    for _ in range(3):
        missing = _get(client, "/public")
        assert missing.json()["error"] == "missing_credential"
    for _ in range(3):
        no_scope = _get(client, "/profile", credential=data["api_key"])
        assert no_scope.json()["error"] == "insufficient_scope"
    for _ in range(3):
        bad = _get(client, "/public", credential="ak_x.y")
        assert bad.json()["error"] == "invalid_credential"

    # The credential still has its full quota on the authorized route.
    statuses = [
        _get(client, "/public", credential=data["api_key"]).status_code
        for _ in range(3)
    ]
    assert statuses == [200, 200, 200], statuses
    # Fourth now crosses the boundary.
    assert _get(client, "/public", credential=data["api_key"]).status_code == 429


def test_rate_limit_is_per_credential(client):
    a = issue_api_key(client, ["read:public"])
    b = issue_api_key(client, ["read:public"])
    # Exhaust A's quota; B is independently unaffected.
    for _ in range(3):
        assert _get(client, "/public", credential=a["api_key"]).status_code == 200
    assert _get(client, "/public", credential=a["api_key"]).status_code == 429
    assert _get(client, "/public", credential=b["api_key"]).status_code == 200


def test_revoked_and_expired_keys_are_rejected_uniformly(client, clock):
    data = issue_api_key(client, ["read:public"])
    revoke = client.post(f"/auth/revoke/{data['key_id']}")
    assert revoke.status_code == 200
    resp = _get(client, "/public", credential=data["api_key"])
    # Edge hides revoked vs expired vs unknown behind invalid_credential.
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_credential"

    exp = issue_api_key(client, ["read:public"], ttl=10)  # t=1000 -> 1010
    clock.set(1011)
    resp = _get(client, "/public", credential=exp["api_key"])
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_credential"
