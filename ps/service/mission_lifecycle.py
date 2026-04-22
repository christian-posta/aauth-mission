"""Mission proposal and lifecycle (protocol §Mission Creation)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ps.models import DeferredResponse, Mission, MissionOutcome, MissionProposal


class MissionLifecycle(ABC):
    """Agent-facing `mission_endpoint` behavior."""

    @abstractmethod
    def create_mission(self, proposal: MissionProposal) -> MissionOutcome:
        """Evaluate proposal; may defer (202) for review or clarification."""

    @abstractmethod
    def get_mission(self, s256: str) -> Mission:
        """Return mission by hash identifier."""
