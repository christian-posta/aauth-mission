"""Permission, audit, and agent interaction (SPEC §Permission, §Audit, §Interaction)."""

from __future__ import annotations

from typing import Union

from ps.impl.backend import utc_now
from ps.impl.mission_state import MissionStatePort
from ps.impl.memory_pending import MemoryPendingStore
from ps.impl.mission_guards import require_active_mission
from ps.models import (
    AgentInteractionRequest,
    AuditRequest,
    DeferredResponse,
    MissionLogEntry,
    MissionLogKind,
    PermissionOutcome,
    PermissionRequest,
    RequirementLevel,
)

PermissionResponse = Union[PermissionOutcome, DeferredResponse]


def _action_in_approved_tools(action: str, approved_tools: object) -> bool:
    if not approved_tools:
        return False
    for t in approved_tools:  # type: ignore[union-attr]
        if isinstance(t, dict) and t.get("name") == action:
            return True
    return False


class PsGovernance:
    """In-memory PS governance endpoints."""

    def __init__(
        self,
        mission: MissionStatePort,
        store: Union[MemoryPendingStore, "DatabasePendingStore"],
        *,
        ps_issuer: str,
    ) -> None:
        self._m = mission
        self._store = store
        self._ps_issuer = ps_issuer.rstrip("/")

    def post_permission(self, req: PermissionRequest) -> PermissionResponse:
        # No mission: spec-permissive — grant. Log only when mission is present.
        if req.mission is None:
            return PermissionOutcome(permission="granted")

        m = require_active_mission(self._m, req.mission)

        if _action_in_approved_tools(req.action, m.approved_tools):
            self._m.append_mission_log(
                m.s256,
                MissionLogEntry(
                    ts=utc_now(),
                    kind=MissionLogKind.PERMISSION,
                    payload={
                        "action": req.action,
                        "description": req.description,
                        "parameters": req.parameters,
                        "result": "granted",
                        "decided_by": "approved_tools",
                    },
                ),
            )
            return PermissionOutcome(permission="granted")

        # Action is outside approved_tools — escalate to the user.
        pid = self._store.create_permission_pending(
            agent_id=req.agent_id,
            owner_id=m.owner_id,
            mission_s256=m.s256,
            action=req.action,
            description=req.description,
            parameters=req.parameters,
        )
        self._store.update_pending(pid, requirement=RequirementLevel.INTERACTION)
        self._m.append_mission_log(
            m.s256,
            MissionLogEntry(
                ts=utc_now(),
                kind=MissionLogKind.PERMISSION,
                payload={
                    "action": req.action,
                    "description": req.description,
                    "parameters": req.parameters,
                    "result": "deferred",
                    "decided_by": "user_pending",
                    "pending_id": pid,
                },
            ),
        )
        out = self._store.get_pending(pid, for_poll=False)
        if isinstance(out, DeferredResponse):
            return out
        raise RuntimeError("unexpected terminal on new permission pending")

    def post_audit(self, req: AuditRequest) -> None:
        m = require_active_mission(self._m, req.mission)
        self._m.append_mission_log(
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
            m = require_active_mission(self._m, req.mission)
            mission_s256 = m.s256
            owner_id = m.owner_id
            self._m.append_mission_log(
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
