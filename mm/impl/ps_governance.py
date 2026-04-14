"""Permission, audit, and agent interaction (SPEC §Permission, §Audit, §Interaction)."""

from __future__ import annotations

from mm.impl.backend import MMBackend, utc_now
from mm.impl.memory_pending import MemoryPendingStore
from mm.impl.mission_guards import require_active_mission
from mm.models import (
    AgentInteractionRequest,
    AuditRequest,
    DeferredResponse,
    MissionLogEntry,
    MissionLogKind,
    PermissionOutcome,
    PermissionRequest,
    RequirementLevel,
)


class PsGovernance:
    """In-memory PS governance endpoints."""

    def __init__(self, backend: MMBackend, store: MemoryPendingStore, *, ps_issuer: str) -> None:
        self._b = backend
        self._store = store
        self._ps_issuer = ps_issuer.rstrip("/")

    def post_permission(self, req: PermissionRequest) -> PermissionOutcome:
        if req.mission is not None:
            m = require_active_mission(self._b, req.mission)
            self._b.append_mission_log(
                m.s256,
                MissionLogEntry(
                    ts=utc_now(),
                    kind=MissionLogKind.PERMISSION,
                    payload={
                        "action": req.action,
                        "description": req.description,
                        "parameters": req.parameters,
                        "result": "granted",
                    },
                ),
            )
        return PermissionOutcome(permission="granted")

    def post_audit(self, req: AuditRequest) -> None:
        m = require_active_mission(self._b, req.mission)
        self._b.append_mission_log(
            m.s256,
            MissionLogEntry(
                ts=utc_now(),
                kind=MissionLogKind.AUDIT,
                payload={
                    "action": req.action,
                    "description": req.description,
                    "parameters": req.parameters,
                    "result": req.result,
                },
            ),
        )

    def post_agent_interaction(self, req: AgentInteractionRequest) -> DeferredResponse:
        mission_s256: str | None = None
        owner_id: str | None = None
        if req.mission is not None:
            m = require_active_mission(self._b, req.mission)
            mission_s256 = m.s256
            owner_id = m.owner_id
            self._b.append_mission_log(
                m.s256,
                MissionLogEntry(
                    ts=utc_now(),
                    kind=MissionLogKind.AGENT_INTERACTION,
                    payload={"type": req.type, "description": req.description},
                ),
            )
        elif req.type == "completion":
            raise ValueError("completion requires mission")

        pid = self._store.create_interaction_pending(
            agent_id=req.agent_id,
            interaction_type=req.type,
            owner_id=owner_id,
            mission_s256=mission_s256,
            summary=req.summary,
            question=req.question,
            relay_url=req.url,
            relay_code=req.code,
            description=req.description,
        )
        self._store.update_pending(pid, requirement=RequirementLevel.INTERACTION)
        out = self._store.get_pending(pid, for_poll=False)
        if isinstance(out, DeferredResponse):
            return out
        raise RuntimeError("unexpected terminal on new interaction pending")
