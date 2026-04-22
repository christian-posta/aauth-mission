"""Minimal ASFederator for demos: returns synthetic auth tokens (no real AS)."""

from __future__ import annotations

import hashlib

from ps.federation.as_federator import ASFederator
from ps.models import AuthTokenResponse, DeferredResponse


class FakeASFederator(ASFederator):
    """Issues deterministic fake JWT-shaped strings; does not perform HTTP to an AS."""

    def request_auth_token(
        self,
        resource_token: str,
        agent_token: str,
        upstream_token: str | None,
    ) -> AuthTokenResponse | DeferredResponse:
        digest = hashlib.sha256(
            f"{resource_token}:{agent_token}:{upstream_token or ''}".encode()
        ).hexdigest()[:32]
        return AuthTokenResponse(auth_token=f"aa-auth.fake.{digest}", expires_in=3600)

    def provide_claims(self, pending_url: str, claims: dict[str, object]) -> AuthTokenResponse | DeferredResponse:
        return AuthTokenResponse(auth_token=f"aa-auth.fake.claims.{len(claims)}", expires_in=3600)

    def poll_as_pending(self, pending_url: str) -> AuthTokenResponse | DeferredResponse:
        return AuthTokenResponse(auth_token="aa-auth.fake.polled", expires_in=3600)
