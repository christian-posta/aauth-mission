"""In-memory MissionControl."""

from __future__ import annotations

from dataclasses import replace

from ps.exceptions import NotFoundError
from ps.impl.backend import PSBackend
from ps.models import Mission, MissionLogEntry, MissionState
from ps.service.mission_control import MissionControl


class MemoryMissionControl(MissionControl):
    def __init__(self, backend: PSBackend) -> None:
        self._b = backend

    def list_missions(self, agent_id: str | None, state: MissionState | None) -> list[Mission]:
        out = list(self._b.missions.values())
        if agent_id is not None:
            out = [m for m in out if m.agent_id == agent_id]
        if state is not None:
            out = [m for m in out if m.state == state]
        return sorted(out, key=lambda m: m.approved_at, reverse=True)

    def list_missions_for_owner(self, owner_id: str) -> list[Mission]:
        out = [m for m in self._b.missions.values() if m.owner_id == owner_id]
        return sorted(out, key=lambda m: m.approved_at, reverse=True)

    def inspect_mission(self, s256: str) -> Mission:
        m = self._b.missions.get(s256)
        if m is None:
            raise NotFoundError("unknown mission")
        return m

    def mission_log(self, s256: str) -> list[MissionLogEntry]:
        if s256 not in self._b.missions:
            raise NotFoundError("unknown mission")
        return list(self._b.mission_log.get(s256, []))

    def terminate_mission(self, s256: str) -> Mission:
        m = self.inspect_mission(s256)
        if m.state != MissionState.ACTIVE:
            raise ValueError("can only terminate an active mission")
        updated = replace(m, state=MissionState.TERMINATED)
        self._b.missions[s256] = updated
        return updated
