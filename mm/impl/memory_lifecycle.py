"""In-memory MissionLifecycle."""

from __future__ import annotations

from dataclasses import replace

from mm.exceptions import NotFoundError
from mm.impl.backend import MMBackend
from mm.impl.memory_pending import MemoryPendingStore
from mm.impl.mission_utils import mission_from_proposal
from mm.models import Mission, MissionOutcome, MissionProposal, MissionState, RequirementLevel
from mm.service.mission_lifecycle import MissionLifecycle


class MemoryMissionLifecycle(MissionLifecycle):
    def __init__(
        self,
        backend: MMBackend,
        pending_store: MemoryPendingStore,
        *,
        auto_approve_mission: bool = True,
    ) -> None:
        self._b = backend
        self._pending = pending_store
        self._auto_approve_mission = auto_approve_mission

    def create_mission(self, proposal: MissionProposal) -> MissionOutcome:
        if self._auto_approve_mission:
            m = mission_from_proposal(proposal)
            self._b.missions[m.s256] = m
            return m
        pid = self._pending.create_pending(proposal)
        self._pending.update_pending(pid, requirement=RequirementLevel.INTERACTION)
        out = self._pending.get_pending(pid, for_poll=False)
        if isinstance(out, Mission):
            raise RuntimeError("unexpected mission before approval")
        return out

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
