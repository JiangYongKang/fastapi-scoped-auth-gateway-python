"""Scope-based access decision (default-deny)."""

from __future__ import annotations

from auth_gateway.models import Principal


class Authorizer:
    def has_scope(self, principal: Principal, required_scope: str) -> bool:
        """Default deny: no declared scope means no access.

        Scopes are compared literally (no wildcard/implication rules), which
        keeps the decision trivially explainable.
        """
        if not principal.scopes:
            return False
        return required_scope in principal.scopes
