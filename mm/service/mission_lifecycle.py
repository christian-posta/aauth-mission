"""Mission proposal and lifecycle (protocol §Mission Creation, §Mission Management)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from mm.models import DeferredResponse, Mission, MissionOutcome, MissionProposal, MissionState


class MissionLifecycle(ABC):
    """Agent-facing `mission_endpoint` behavior."""

    @abstractmethod
    def create_mission(self, proposal: MissionProposal) -> MissionOutcome:
        """Evaluate proposal; may defer (202) for review or clarification."""

    @abstractmethod
    def get_mission(self, s256: str) -> Mission:
        """Return mission by hash identifier."""

    @abstractmethod
    def update_mission_state(self, s256: str, new_state: MissionState) -> Mission:
        """Apply a state transition (not necessarily full admin policy)."""
