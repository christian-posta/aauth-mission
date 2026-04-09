"""In-memory MissionLifecycle."""

from __future__ import annotations

from dataclasses import replace

from mm.exceptions import NotFoundError
from mm.impl.backend import MMBackend
from mm.impl.mission_utils import mission_from_proposal
from mm.models import Mission, MissionOutcome, MissionProposal, MissionState
from mm.service.mission_lifecycle import MissionLifecycle


class MemoryMissionLifecycle(MissionLifecycle):
    def __init__(self, backend: MMBackend) -> None:
        self._b = backend

    def create_mission(self, proposal: MissionProposal) -> MissionOutcome:
        m = mission_from_proposal(proposal)
        self._b.missions[m.s256] = m
        return m

    def get_mission(self, s256: str) -> Mission:
        m = self._b.missions.get(s256)
        if m is None:
            raise NotFoundError("unknown mission")
        return m

    def update_mission_state(self, s256: str, new_state: MissionState) -> Mission:
        m = self.get_mission(s256)
        updated = replace(m, state=new_state)
        self._b.missions[s256] = updated
        return updated
