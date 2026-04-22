"""Internal storage for deferred (202) flows (protocol §Deferred Response State Machine)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ps.models import (
    AuthTokenResponse,
    InteractionTerminalResult,
    Mission,
    MissionProposal,
    PendingStatus,
    PendingStoreValue,
    RequirementLevel,
    TokenRequest,
)


class PendingRequestStore(ABC):
    """Backing store for pending URLs; not exposed as public REST."""

    @abstractmethod
    def create_pending(self, original_request: TokenRequest | MissionProposal) -> str:
        """Create a new pending record; return `pending_id` (path segment)."""

    @abstractmethod
    def get_pending(self, pending_id: str, *, for_poll: bool = False) -> PendingStoreValue:
        """Return current deferred snapshot or terminal success (token or mission).

        ``for_poll=True`` enables polling semantics (e.g. rate limiting) for GET on the pending URL.
        """

    @abstractmethod
    def update_pending(
        self,
        pending_id: str,
        *,
        status: PendingStatus | None = None,
        requirement: RequirementLevel | None = None,
        clarification: str | None = None,
        timeout: int | None = None,
        options: list[str] | None = None,
    ) -> None:
        """Update non-terminal pending state (e.g. status → interacting)."""

    @abstractmethod
    def resolve_pending(
        self, pending_id: str, result: AuthTokenResponse | Mission | InteractionTerminalResult
    ) -> None:
        """Mark success; subsequent reads should reflect completion."""

    @abstractmethod
    def fail_pending(self, pending_id: str, error: str) -> None:
        """Record terminal failure (implementation may map to 403/500)."""

    @abstractmethod
    def delete_pending(self, pending_id: str) -> None:
        """Cancel: subsequent access returns 410 Gone per protocol."""

    @abstractmethod
    def assert_agent_owns_pending(self, pending_id: str, agent_id: str) -> None:
        """Ensure the pending row belongs to this agent (else raise NotFoundError)."""

    @abstractmethod
    def set_callback_url(self, pending_id: str, callback_url: str | None) -> None:
        """Optional redirect after consent (protocol §User Interaction)."""
