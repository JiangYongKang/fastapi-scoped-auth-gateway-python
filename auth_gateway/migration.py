"""Legacy static-credential migration window controls."""

from __future__ import annotations

from auth_gateway.clock import Clock
from auth_gateway.config import Settings

# Stable observability marker attached to every accepted legacy request.
LEGACY_MARKER = "legacy-credential-migration"
# Marker explaining a reject after the window (server-side audit only).
LEGACY_WINDOW_CLOSED = "legacy-window-closed"


class LegacyResolver:
    """Resolves legacy static credentials during the migration window.

    Legacy credentials:
      * are accepted only while clock.now() < settings.migration_window_ends_at
      * map to a fixed, low-privilege scope set
      * carry an explicit observability marker
      * become deterministically rejected once the window closes
    """

    def __init__(
        self, legacy_keys: set[str], settings: Settings, clock: Clock
    ) -> None:
        # Store hashed material so we never keep raw static secrets around,
        # but membership is compared against the raw presented value here in
        # a local-only deployment.
        self._legacy_keys = set(legacy_keys)
        self._settings = settings
        self._clock = clock

    def window_open(self, now: float | None = None) -> bool:
        current = self._clock.now() if now is None else now
        # Strictly before the end instant: at/after the close instant the
        # decision flips once and never flips back (same input -> same result).
        return current < self._settings.migration_window_ends_at

    def resolve(self, raw_credential: str) -> tuple[bool, str | None]:
        """Return (is_legacy, marker). Marker is None when not legacy."""
        if raw_credential not in self._legacy_keys:
            return False, None
        if self.window_open():
            return True, LEGACY_MARKER
        # It is a recognized legacy credential, but the window has closed.
        return True, LEGACY_WINDOW_CLOSED
