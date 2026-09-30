"""Failure reasons must be distinguishable and storage errors must not leak."""

from __future__ import annotations

import logging

from tests.conftest import issue_api_key

log = logging.getLogger("tests.errors")


def test_four_resource_edge_reasons_are_distinct(client):
    # 1) missing
    missing = client.get("/public")
    # 2) invalid
    invalid = client.get(
        "/public", headers={"Authorization": "Bearer ak_nope.zzz"}
    )
    # 3) insufficient scope (valid credential, wrong scope)
    key = issue_api_key(client, ["read:public"])
    insufficient = client.get(
        "/profile", headers={"Authorization": f"Bearer {key['api_key']}"}
    )
    # 4) rate limited
    for _ in range(3):
        client.get("/public", headers={"Authorization": f"Bearer {key['api_key']}"})
    limited = client.get(
        "/public", headers={"Authorization": f"Bearer {key['api_key']}"}
    )

    codes = {
        (missing.status_code, missing.json()["error"]),
        (invalid.status_code, invalid.json()["error"]),
        (insufficient.status_code, insufficient.json()["error"]),
        (limited.status_code, limited.json()["error"]),
    }
    log.info("distinct edge outcomes: %s", sorted(codes))
    assert codes == {
        (401, "missing_credential"),
        (401, "invalid_credential"),
        (401, "insufficient_scope"),
        (429, "rate_limited"),
    }


def test_error_responses_do_not_leak_resource_or_credential(client):
    # A wrong-scope call must not reveal whether the resource exists beyond
    # a uniform description, and must not echo the credential or other ids.
    key = issue_api_key(client, ["read:public"])
    resp = client.get(
        "/profile", headers={"Authorization": f"Bearer {key['api_key']}"}
    )
    body = resp.json()
    assert body["error_description"] == "not permitted for this resource"
    assert key["api_key"] not in repr(body)
    assert key["key_id"] not in repr(body)

    # Invalid credential gives a generic description with no state detail.
    bad = client.get("/public", headers={"Authorization": "Bearer ak_a.b"})
    assert bad.json()["error_description"] == "authentication failed"


def test_storage_failure_is_mapped_to_generic_500(settings, clock, auditor):
    from fastapi.testclient import TestClient

    from auth_gateway.app import create_app
    from auth_gateway.errors import StorageError
    from auth_gateway.storage import InMemoryStore

    class FlakyStore(InMemoryStore):
        def get_api_key(self, key_id):
            raise StorageError("simulated db outage")

    app = create_app(
        settings,
        legacy_keys=set(),
        auditor=auditor,
        clock=clock,
        store=FlakyStore(),
    )
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.get(
            "/public", headers={"Authorization": "Bearer ak_real.secretpart"}
        )
        assert resp.status_code == 500
        body = resp.json()
        assert body["error"] == "internal_error"
        # Internal detail must not reach the client.
        assert "simulated db outage" not in repr(body)
        assert "StorageError" not in repr(body)


def test_storage_failure_during_issue_is_generic(settings, clock, auditor):
    from fastapi.testclient import TestClient

    from auth_gateway.app import create_app
    from auth_gateway.errors import StorageError
    from auth_gateway.storage import InMemoryStore

    class FailOnceStore(InMemoryStore):
        def put_api_key(self, record):
            raise StorageError("disk full")

    app = create_app(
        settings,
        legacy_keys=set(),
        auditor=auditor,
        clock=clock,
        store=FailOnceStore(),
    )
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.post("/auth/api-keys", json={"scopes": ["read:public"]})
        assert resp.status_code == 500
        assert resp.json()["error"] == "internal_error"
        assert "disk full" not in resp.text
