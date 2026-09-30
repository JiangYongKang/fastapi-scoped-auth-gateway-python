"""Legacy credentials before/after the migration window."""

from __future__ import annotations

import logging

from tests.conftest import LEGACY_KEY

log = logging.getLogger("tests.migration")


def _access(client, path, credential):
    resp = client.get(
        path, headers={"Authorization": f"Bearer {credential}"}
    )
    log.info(
        "INPUT %s legacy_key=%s -> DECISION status=%s body=%s",
        path, credential == LEGACY_KEY, resp.status_code, resp.json()
    )
    return resp


def test_legacy_credential_works_during_window_with_marker(client, auditor):
    resp = _access(client, "/public", LEGACY_KEY)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["legacy"] is True
    # Low-privilege scope only.
    assert body["scopes"] == ["read:public"]

    # Explicit observability marker in the audit trail.
    legacy_records = [
        r for r in auditor.records_for(LEGACY_KEY) if r.event == "access"
    ]
    assert legacy_records, "expected an audit record for the legacy key"
    allowed = [r for r in legacy_records if r.decision == "allow"]
    assert allowed, legacy_records
    assert allowed[0].migration_marker == "legacy-credential-migration"
    assert allowed[0].legacy is True


def test_legacy_credential_is_low_privilege(client):
    # It only holds read:public, so profile/admin must be denied.
    resp = _access(client, "/profile", LEGACY_KEY)
    assert resp.status_code == 401
    assert resp.json()["error"] == "insufficient_scope"


def test_legacy_credential_dead_after_window(client, clock, auditor):
    # Boundary: window ends at t=2000; exactly at/after it must fail.
    clock.set(2000.0)
    resp = _access(client, "/public", LEGACY_KEY)
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_credential"

    # Audit must retain the true reason even though the client does not.
    closes = [
        r for r in auditor.records_for(LEGACY_KEY)
        if r.reason == "legacy_revoked_post_window"
    ]
    assert closes, "expected post-window audit reason"

    # Moving further in time cannot bring it back.
    clock.set(5000.0)
    again = _access(client, "/public", LEGACY_KEY)
    assert again.status_code == 401
    assert again.json()["error"] == "invalid_credential"


def test_legacy_decision_is_stable_no_flapping(settings, clock):
    """Same credential at the same time must always decide identically.

    Use a dedicated app with a high quota so rate limiting cannot be
    mistaken for a lifecycle decision flip.
    """
    from dataclasses import replace

    from fastapi.testclient import TestClient

    from auth_gateway.app import create_app
    from auth_gateway.audit import Auditor

    local_settings = replace(settings, rate_limit_per_window=10_000)
    local_app = create_app(
        local_settings,
        legacy_keys={LEGACY_KEY},
        auditor=Auditor(),
        clock=clock,
    )
    with TestClient(local_app) as client:
        clock.set(1500.0)  # inside window
        in_window = {
            _access(client, "/public", LEGACY_KEY).status_code for _ in range(5)
        }
        assert in_window == {200}, in_window

        clock.set(2000.0)  # closed
        post_window = {
            _access(client, "/public", LEGACY_KEY).status_code for _ in range(5)
        }
        assert post_window == {401}, post_window


def test_unknown_string_after_window_is_plain_invalid(client, clock):
    clock.set(5000.0)
    resp = _access(client, "/public", "some-random-unknown-value")
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_credential"
