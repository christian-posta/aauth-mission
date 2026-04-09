"""In-memory MissionControl."""

from __future__ import annotations

from dataclasses import replace

from mm.exceptions import NotFoundError
from mm.impl.backend import MMBackend
from mm.models import Mission, MissionState
from mm.service.mission_control import MissionControl


class MemoryMissionControl(MissionControl):
    def __init__(self, backend: MMBackend) -> None:
        self._b = backend

    def list_missions(self, agent_id: str | None, state: MissionState | None) -> list[Mission]:
        out = list(self._b.missions.values())
        if agent_id is not None:
            out = [m for m in out if m.agent_id == agent_id]
        if state is not None:
            out = [m for m in out if m.state == state]
        return sorted(out, key=lambda m: m.created_at, reverse=True)

    def list_missions_for_owner(self, owner_id: str) -> list[Mission]:
        out = [m for m in self._b.missions.values() if m.owner_id == owner_id]
        return sorted(out, key=lambda m: m.created_at, reverse=True)

    def inspect_mission(self, s256: str) -> Mission:
        m = self._b.missions.get(s256)
        if m is None:
            raise NotFoundError("unknown mission")
        return m

    def _set_state(self, s256: str, new_state: MissionState) -> Mission:
        m = self.inspect_mission(s256)
        updated = replace(m, state=new_state)
        self._b.missions[s256] = updated
        return updated

    def suspend_mission(self, s256: str) -> Mission:
        return self._set_state(s256, MissionState.SUSPENDED)

    def resume_mission(self, s256: str) -> Mission:
        return self._set_state(s256, MissionState.ACTIVE)

    def revoke_mission(self, s256: str) -> Mission:
        return self._set_state(s256, MissionState.REVOKED)

    def complete_mission(self, s256: str) -> Mission:
        return self._set_state(s256, MissionState.COMPLETED)
