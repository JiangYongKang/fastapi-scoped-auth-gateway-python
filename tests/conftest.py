"""Shared pytest fixtures with a deterministic clock and local store."""

from __future__ import annotations

import pytest

from auth_gateway.audit import Auditor
from auth_gateway.authorization import Authorizer
from auth_gateway.clock import FixedClock
from auth_gateway.config import Settings
from auth_gateway.app import create_app
from auth_gateway.issuer import Issuer
from auth_gateway.migration import LegacyResolver
from auth_gateway.ratelimit import RateLimiter
from auth_gateway.service import AuthService
from auth_gateway.storage import InMemoryStore


@pytest.fixture
def clock() -> FixedClock:
    raise NotImplementedError


@pytest.fixture
def settings() -> Settings:
    raise NotImplementedError


@pytest.fixture
def auditor() -> Auditor:
    raise NotImplementedError


@pytest.fixture
def store() -> InMemoryStore:
    raise NotImplementedError


@pytest.fixture
def components(store, settings, clock, auditor) -> dict:
    raise NotImplementedError


@pytest.fixture
def app(settings, clock, auditor):
    raise NotImplementedError


@pytest.fixture
def client(app):
    raise NotImplementedError
