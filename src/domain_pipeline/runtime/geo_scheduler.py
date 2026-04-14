"""Geo provider ordering helpers for deterministic host-level selection."""

from __future__ import annotations

import threading

from .pure_helpers import ordered_geo_provider_names


class GeoProviderScheduler:
    """Return the one effective provider without rotation or fallback."""

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def ordered_provider_names(
        self, configured_provider_name: str, *, host_index: int | None = None
    ) -> list[str]:
        """Return the deterministic provider order for the current source lookup."""
        del host_index
        with self._lock:
            return list(ordered_geo_provider_names(configured_provider_name))
