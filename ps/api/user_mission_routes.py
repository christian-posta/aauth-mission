"""Legal-user mission control: GET/PATCH /user/missions, GET /user/consent."""

from __future__ import annotations

from typing import Any

from ps.api.admin_routes import patch_mission
from ps.exceptions import ForbiddenOwnerError, NotFoundError
from ps.impl.memory_pending import CONSENT_UI_PATH, MemoryPendingStore
from ps.models import Mission, MissionState
from ps.service.mission_control import MissionControl


def list_user_missions_route(control: MissionControl, user_id: str) -> list[Mission]:
    """GET `/user/missions`."""
    return control.list_missions_for_owner(user_id)


def get_user_mission_route(control: MissionControl, s256: str, user_id: str) -> Mission:
    """GET `/user/missions/{s256}` — must match owner."""
    try:
        m = control.inspect_mission(s256)
    except NotFoundError:
        raise
    if m.owner_id != user_id:
        raise ForbiddenOwnerError()
    return m


def patch_user_mission_route(
    control: MissionControl, s256: str, user_id: str, new_state: MissionState
) -> Mission:
    """PATCH `/user/missions/{s256}` — must match owner."""
    _ = get_user_mission_route(control, s256, user_id)
    return patch_mission(control, s256, new_state)


def user_consent_queue(store: MemoryPendingStore, owner_id: str) -> list[dict[str, Any]]:
    """GET `/user/consent` — pending interaction rows for this owner."""
    recs = store.list_interaction_pending_for_owner(owner_id)
    interaction_url = f"{store.interaction_base_url}{CONSENT_UI_PATH}"
    out: list[dict[str, Any]] = []
    for rec in recs:
        agent_id = (
            rec.token_request.agent_id
            if rec.token_request is not None
            else (rec.mission_proposal.agent_id if rec.mission_proposal is not None else "")
        )
        out.append(
            {
                "pending_id": rec.pending_id,
                "code": rec.interaction_code,
                "kind": rec.kind,
                "agent_id": agent_id,
                "interaction_url": interaction_url,
            }
        )
    return out
