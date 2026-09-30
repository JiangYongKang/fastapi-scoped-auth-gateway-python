"""Configuration for the auth gateway.

All settings come from environment variables (prefix ``AUTH_``) so the
service stays dependency-free and easy to run locally.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


def _env_seconds(name: str, default: float) -> float:
    raw = os.environ.get(name)
    return float(raw) if raw not in (None, "") else default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw not in (None, "") else default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _parse_migration_end(raw: str | None) -> float | None:
    if raw is None or raw == "":
        return None
    # Accept either a unix timestamp or an ISO-8601 datetime.
    try:
        return float(raw)
    except ValueError:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()


@dataclass(frozen=True)
class Settings:
    #: Lifetime of short-lived access tokens.
    access_token_ttl: timedelta = timedelta(minutes=15)
    #: Lifetime of refresh tokens (rotated on every use).
    refresh_token_ttl: timedelta = timedelta(days=7)
    #: Default TTL applied to newly issued API keys; None = never expires.
    api_key_default_ttl: timedelta | None = timedelta(days=90)
    #: Fixed rate-limit window.
    rate_limit_window: timedelta = timedelta(minutes=1)
    #: Max requests per credential per window.
    rate_limit_max_requests: int = 100
    #: Scopes granted to legacy static credentials during migration.
    legacy_scopes: frozenset[str] = frozenset({"read:public"})
    #: Master switch for the migration window.
    migration_enabled: bool = True
    #: Unix timestamp after which legacy credentials are fully disabled.
    migration_ends_at: float | None = None
    #: Legacy credentials as ``identifier -> secret`` mapping.
    legacy_credentials: dict[str, str] = field(default_factory=dict)
    #: Header carrying the legacy static credential.
    legacy_header_name: str = "X-Legacy-Credential"

    def legacy_active(self, now_ts: float) -> bool:
        """Whether legacy credentials are accepted at ``now_ts``.

        The decision is a single, stable function of the clock: enabled and
        either no end configured or the end not yet reached.
        """
        if not self.migration_enabled:
            return False
        return self.migration_ends_at is None or now_ts < self.migration_ends_at


def get_settings() -> Settings:
    api_key_ttl = _env_seconds("AUTH_API_KEY_DEFAULT_TTL_SECONDS", 90 * 24 * 3600)
    raw_legacy = os.environ.get("AUTH_LEGACY_CREDENTIALS", "")
    try:
        legacy_credentials: dict[str, str] = (
            json.loads(raw_legacy) if raw_legacy else {"legacy-static-key": "legacy-static-secret"}
        )
    except json.JSONDecodeError:
        legacy_credentials = {}

    return Settings(
        access_token_ttl=timedelta(
            seconds=_env_seconds("AUTH_ACCESS_TOKEN_TTL_SECONDS", 15 * 60)
        ),
        refresh_token_ttl=timedelta(
            seconds=_env_seconds("AUTH_REFRESH_TOKEN_TTL_SECONDS", 7 * 24 * 3600)
        ),
        api_key_default_ttl=(
            timedelta(seconds=api_key_ttl) if api_key_ttl > 0 else None
        ),
        rate_limit_window=timedelta(
            seconds=_env_seconds("AUTH_RATE_LIMIT_WINDOW_SECONDS", 60)
        ),
        rate_limit_max_requests=_env_int("AUTH_RATE_LIMIT_MAX", 100),
        legacy_scopes=frozenset(
            s.strip()
            for s in os.environ.get("AUTH_LEGACY_SCOPES", "read:public").split(",")
            if s.strip()
        ),
        migration_enabled=_env_bool("AUTH_MIGRATION_ENABLED", True),
        migration_ends_at=_parse_migration_end(os.environ.get("AUTH_MIGRATION_ENDS_AT")),
        legacy_credentials=legacy_credentials,
        legacy_header_name=os.environ.get("AUTH_LEGACY_HEADER", "X-Legacy-Credential"),
    )
