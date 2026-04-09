"""Administrative mission control (protocol §Mission Control, optional endpoint)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from mm.models import Mission, MissionState


class MissionControl(ABC):
    """List, inspect, and lifecycle operations for missions."""

    @abstractmethod
    def list_missions(self, agent_id: str | None, state: MissionState | None) -> list[Mission]:
        """Filter missions by agent and/or state."""

    @abstractmethod
    def inspect_mission(self, s256: str) -> Mission:
        """Detail view including delegation/audit (implementation-defined)."""

    @abstractmethod
    def suspend_mission(self, s256: str) -> Mission:
        """Set mission to suspended."""

    @abstractmethod
    def resume_mission(self, s256: str) -> Mission:
        """Resume from suspended to active."""

    @abstractmethod
    def revoke_mission(self, s256: str) -> Mission:
        """Terminal revoke."""

    @abstractmethod
    def complete_mission(self, s256: str) -> Mission:
        """Terminal complete."""
