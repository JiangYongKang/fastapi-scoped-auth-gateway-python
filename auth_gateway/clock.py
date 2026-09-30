"""Time abstraction so expiry / migration decisions stay deterministic."""

from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    def now(self) -> float:
        """Return current unix epoch seconds (monotonic wall clock)."""
        ...


class SystemClock:
    def now(self) -> float:
        return time.time()


class FixedClock:
    """Deterministic clock used by tests for window/expiry boundaries."""

    def __init__(self, current: float = 0.0) -> None:
        self.current = current

    def now(self) -> float:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += seconds

    def set(self, value: float) -> None:
        self.current = value
