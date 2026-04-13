"""Agent token and pending URL handling (protocol §MM Token Endpoint, §Agent Response to Clarification)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from mm.models import AuthTokenResponse, DeferredResponse, PendingPollOutcome, TokenOutcome, TokenRequest


class TokenBroker(ABC):
    """`token_endpoint` and pending URL operations for agents."""

    @abstractmethod
    def request_token(self, request: TokenRequest) -> TokenOutcome:
        """POST /token — may return auth token or deferred response."""

    @abstractmethod
    def get_pending(self, pending_id: str, agent_id: str) -> PendingPollOutcome:
        """GET pending URL — poll until 200 or terminal error."""

    @abstractmethod
    def post_clarification_response(self, pending_id: str, agent_id: str, response_text: str) -> DeferredResponse:
        """POST `clarification_response` to pending URL."""

    @abstractmethod
    def post_updated_request(
        self,
        pending_id: str,
        agent_id: str,
        new_resource_token: str,
        justification: str | None,
    ) -> DeferredResponse:
        """POST updated `resource_token` to pending URL."""

    @abstractmethod
    def cancel_request(self, pending_id: str, agent_id: str) -> None:
        """DELETE pending URL — withdraw request."""
