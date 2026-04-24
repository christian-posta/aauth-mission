"""Resolve resource issuer JWKS for :func:`aauth.verify_resource_token`."""

from __future__ import annotations

import time
from typing import Any, Protocol

from ps.federation.sync_http import discover_jwks_via_metadata


class ResourceJWKSFetcher(Protocol):
    """Callable ``iss -> JWKS`` for :func:`aauth.verify_resource_token`."""

    def __call__(self, iss: str) -> dict[str, Any] | None: ...


class ResourceJWKSResolver:
    """Callable ``(iss: str) -> JWKS dict | None``."""

    def __init__(self, *, cache_ttl_seconds: float = 300.0) -> None:
        self._ttl = cache_ttl_seconds
        self._cache: dict[str, tuple[dict[str, Any], float]] = {}

    def __call__(self, iss: str) -> dict[str, Any] | None:
        key = iss.rstrip("/")
        hit = self._cache.get(key)
        if hit:
            jwks, ts = hit
            if time.monotonic() - ts <= self._ttl:
                return jwks
            del self._cache[key]
        try:
            jwks = discover_jwks_via_metadata(key, "aauth-resource.json")
        except (OSError, ValueError):
            return None
        self._cache[key] = (jwks, time.monotonic())
        return jwks
