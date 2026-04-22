"""Administrative mission control (protocol §Mission Control, optional endpoint)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ps.models import Mission, MissionLogEntry, MissionState


class MissionControl(ABC):
    """List, inspect, and lifecycle operations for missions."""

    @abstractmethod
    def list_missions(self, agent_id: str | None, state: MissionState | None) -> list[Mission]:
        """Filter missions by agent and/or state."""

    @abstractmethod
    def list_missions_for_owner(self, owner_id: str) -> list[Mission]:
        """Missions whose owner_id matches (legal user scope)."""

    @abstractmethod
    def inspect_mission(self, s256: str) -> Mission:
        """Detail view."""

    @abstractmethod
    def mission_log(self, s256: str) -> list[MissionLogEntry]:
        """Ordered mission log entries."""

    @abstractmethod
    def terminate_mission(self, s256: str) -> Mission:
        """Set mission to terminated (only transition from active)."""
