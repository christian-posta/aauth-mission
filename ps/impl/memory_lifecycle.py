"""In-memory MissionLifecycle."""

from __future__ import annotations

from typing import Union

from ps.exceptions import NotFoundError
from ps.impl.backend import utc_now
from ps.impl.memory_pending import MemoryPendingStore
from ps.impl.mission_state import MissionStatePort
from ps.impl.mission_utils import mission_from_proposal
from ps.models import (
    Mission,
    MissionLogEntry,
    MissionLogKind,
    MissionOutcome,
    MissionProposal,
    RequirementLevel,
)
from ps.service.mission_lifecycle import MissionLifecycle


class MemoryMissionLifecycle(MissionLifecycle):
    def __init__(
        self,
        mission: MissionStatePort,
        pending_store: Union[MemoryPendingStore, "DatabasePendingStore"],
        *,
        ps_issuer: str,
        auto_approve_mission: bool = True,
    ) -> None:
        self._m = mission
        self._pending = pending_store
        self._ps_issuer = ps_issuer.rstrip("/")
        self._auto_approve_mission = auto_approve_mission

    def _record_mission(self, m: Mission) -> None:
        self._m.set_mission(m)
        self._m.append_mission_log(
            m.s256,
            MissionLogEntry(ts=utc_now(), kind=MissionLogKind.MISSION_APPROVED, payload={"agent_id": m.agent_id}),
        )

    def create_mission(self, proposal: MissionProposal) -> MissionOutcome:
        if self._auto_approve_mission:
            m = mission_from_proposal(proposal, self._ps_issuer)
            self._record_mission(m)
            return m
        pid = self._pending.create_pending(proposal)
        self._pending.update_pending(pid, requirement=RequirementLevel.INTERACTION)
        out = self._pending.get_pending(pid, for_poll=False)
        if isinstance(out, Mission):
            raise RuntimeError("unexpected mission before approval")
        return out

    def get_mission(self, s256: str) -> Mission:
        m = self._m.get_mission(s256)
        if m is None:
            raise NotFoundError("unknown mission")
        return m
