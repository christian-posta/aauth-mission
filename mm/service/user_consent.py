"""User interaction and consent (protocol §User Interaction, interaction URL)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from mm.models import ConsentContext, UserDecision


class UserConsent(ABC):
    """User-facing consent surface (session-based auth, not agent HTTP signatures)."""

    @abstractmethod
    def get_consent_context(self, code: str) -> ConsentContext:
        """Resolve interaction `code` to what the user should see."""

    @abstractmethod
    def record_decision(self, pending_id: str, decision: UserDecision) -> None:
        """Apply approve / deny / clarification question."""

    @abstractmethod
    def mark_interacting(self, pending_id: str) -> None:
        """User arrived; pending body `status` becomes `interacting`."""
