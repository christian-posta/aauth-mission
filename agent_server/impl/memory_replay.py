"""In-memory replay protection cache."""

from __future__ import annotations

import time

from agent_server.exceptions import ReplayError


class ReplayCache:
    """Caches (key_thumbprint, created_ts) pairs to reject replayed HTTP signatures.

    A replayed request is one where the same key presents the same `created` timestamp
    within the signature window. The window is per spec §HTTP Signature Verification.
    """

    def __init__(self, window_seconds: int = 60) -> None:
        self._window = window_seconds
        # key: (thumbprint, created_ts) -> recorded_at (monotonic)
        self._seen: dict[tuple[str, int], float] = {}

    def check_and_record(self, thumbprint: str, created_ts: int) -> None:
        """Raise ReplayError if (thumbprint, created_ts) was seen before; otherwise record it."""
        self._purge_stale()
        key = (thumbprint, created_ts)
        if key in self._seen:
            raise ReplayError(f"Replayed signature: {thumbprint} created={created_ts}")
        self._seen[key] = time.monotonic()

    def _purge_stale(self) -> None:
        now = time.monotonic()
        cutoff = now - (self._window + 5)  # small buffer beyond window
        stale = [k for k, ts in self._seen.items() if ts < cutoff]
        for k in stale:
            del self._seen[k]
