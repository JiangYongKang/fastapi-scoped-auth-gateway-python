"""Configuration for the auth gateway.

All settings are plain, locally-resolvable values (no external services).
Environment variables override defaults so tests can set explicit windows.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    # Access-token lifetime in seconds (short-lived).
    access_token_ttl: int = 900
    # Refresh-token lifetime in seconds.
    refresh_token_ttl: int = 60 * 60 * 24 * 7
    # API keys without an explicit expiry use this lifetime.
    default_api_key_ttl: int = 60 * 60 * 24 * 90
    # Default per-credential request quota per rate-limit window.
    rate_limit_per_window: int = 100
    # Rate-limit window length in seconds (fixed window).
    rate_limit_window_seconds: int = 60
    # Legacy credentials are accepted (as low-privilege) only while
    # now < migration_window_ends_at (unix epoch seconds).
    migration_window_ends_at: int = 0
    # Scope granted to legacy static credentials during the migration window.
    legacy_scope: frozenset[str] = frozenset({"read:public"})

    @staticmethod
    def from_env() -> Settings:
        def _int(name: str, default: int) -> int:
            raw = os.environ.get(name)
            return int(raw) if raw not in (None, "") else default

        def _scopes(name: str, default: frozenset[str]) -> frozenset[str]:
            raw = os.environ.get(name)
            if raw in (None, ""):
                return default
            return frozenset(s.strip() for s in raw.split(",") if s.strip())

        return Settings(
            access_token_ttl=_int("AUTH_ACCESS_TOKEN_TTL", 900),
            refresh_token_ttl=_int("AUTH_REFRESH_TOKEN_TTL", 60 * 60 * 24 * 7),
            default_api_key_ttl=_int("AUTH_API_KEY_TTL", 60 * 60 * 24 * 90),
            rate_limit_per_window=_int("AUTH_RATE_LIMIT", 100),
            rate_limit_window_seconds=_int("AUTH_RATE_WINDOW", 60),
            migration_window_ends_at=_int("AUTH_MIGRATION_ENDS_AT", 0),
            legacy_scope=_scopes(
                "AUTH_LEGACY_SCOPE", frozenset({"read:public"})
            ),
        )
