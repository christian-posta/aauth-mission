"""PS-to-AS token endpoint federation (protocol §AS Token Endpoint, §PS-to-AS)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ps.models import AuthTokenResponse, DeferredResponse


class ASFederator(ABC):
    """Call resource AS token endpoints and follow deferred responses."""

    @abstractmethod
    def request_auth_token(
        self,
        resource_token: str,
        agent_token: str,
        upstream_token: str | None,
    ) -> AuthTokenResponse | DeferredResponse:
        """POST to AS `token_endpoint` with resource and agent tokens."""

    @abstractmethod
    def provide_claims(self, pending_url: str, claims: dict[str, object]) -> AuthTokenResponse | DeferredResponse:
        """POST requested identity claims to the AS pending URL for `requirement=claims`."""

    @abstractmethod
    def poll_as_pending(self, pending_url: str) -> AuthTokenResponse | DeferredResponse:
        """GET the AS `Location` pending URL until a terminal response."""
