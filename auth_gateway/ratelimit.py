"""Per-credential fixed-window rate limiting (local state)."""

from __future__ import annotations

import threading


class RateLimiter:
    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        # credential_id -> (window_start_epoch, used_count)
        self._windows: dict[str, tuple[float, int]] = {}

    def _current(self, credential_id: str, now: float) -> tuple[float, int]:
        start, used = self._windows.get(credential_id, (now, 0))
        if now - start >= self.window_seconds:
            # Window elapsed -> start a fresh one (evaluated lazily).
            start, used = now, 0
        return start, used

    def check(self, credential_id: str, now: float) -> bool:
        """Return True if a request is allowed *without* consuming quota."""
        with self._lock:
            _, used = self._current(credential_id, now)
            return used < self.limit

    def consume(self, credential_id: str, now: float) -> int:
        """Consume one slot; return remaining quota in the current window."""
        with self._lock:
            start, used = self._current(credential_id, now)
            used += 1
            self._windows[credential_id] = (start, used)
            return max(0, self.limit - used)
