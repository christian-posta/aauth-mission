"""Resolve agent-server JWKS for ``verify_agent_token`` (trust + optional co-located AS)."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from ps.federation.agent_server_trust import AgentServerTrustRegistry, normalize_issuer
from ps.federation.sync_http import discover_jwks_via_metadata


class DeferredAgentSelfJWKS:
    """Set ``fn`` after the Agent Server container exists (unified portal startup)."""

    def __init__(self) -> None:
        self._fn: Callable[[], dict[str, Any]] | None = None

    def set(self, fn: Callable[[], dict[str, Any]]) -> None:
        self._fn = fn

    def __call__(self) -> dict[str, Any]:
        if self._fn is None:
            raise RuntimeError("Agent self JWKS provider not wired (portal bug)")
        return self._fn()


class AgentServerJWKSResolver:
    """Callable ``(iss: str) -> JWKS dict | None`` for :func:`aauth.verify_agent_token`."""

    def __init__(
        self,
        ps_origin: str,
        trust: AgentServerTrustRegistry,
        self_jwks_provider: Callable[[], dict[str, Any]] | None,
        *,
        cache_ttl_seconds: float = 300.0,
    ) -> None:
        self._ps = normalize_issuer(ps_origin)
        self._trust = trust
        self._self_jwks = self_jwks_provider
        self._ttl = cache_ttl_seconds
        self._cache: dict[str, tuple[dict[str, Any], float]] = {}

    def _get_cached(self, key: str) -> dict[str, Any] | None:
        hit = self._cache.get(key)
        if not hit:
            return None
        jwks, ts = hit
        if time.monotonic() - ts > self._ttl:
            del self._cache[key]
            return None
        return jwks

    def _set_cache(self, key: str, jwks: dict[str, Any]) -> None:
        self._cache[key] = (jwks, time.monotonic())

    def __call__(self, iss: str) -> dict[str, Any] | None:
        niss = normalize_issuer(iss)
        if niss == self._ps:
            if self._self_jwks is None:
                return None
            cached = self._get_cached(f"self:{niss}")
            if cached is not None:
                return cached
            jwks = self._self_jwks()
            self._set_cache(f"self:{niss}", jwks)
            return jwks
        if not self._trust.is_trusted(niss):
            return None
        cached = self._get_cached(f"trusted:{niss}")
        if cached is not None:
            return cached
        try:
            jwks = discover_jwks_via_metadata(niss, "aauth-agent.json")
        except (OSError, ValueError):
            return None
        self._set_cache(f"trusted:{niss}", jwks)
        return jwks
