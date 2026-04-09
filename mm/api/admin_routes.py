"""Admin mission control: GET/PATCH /missions."""

from __future__ import annotations

from mm.models import Mission, MissionState
from mm.service.mission_control import MissionControl


def list_missions_route(
    control: MissionControl,
    agent_id: str | None,
    state: MissionState | None,
) -> list[Mission]:
    """GET `/missions`."""
    return control.list_missions(agent_id, state)


def get_mission_route(control: MissionControl, s256: str) -> Mission:
    """GET `/missions/{s256}`."""
    return control.inspect_mission(s256)


def patch_mission(control: MissionControl, s256: str, new_state: MissionState) -> Mission:
    """PATCH `/missions/{s256}` with body `{ "state": "<MissionState value>" }`."""
    if new_state is MissionState.SUSPENDED:
        return control.suspend_mission(s256)
    if new_state is MissionState.ACTIVE:
        return control.resume_mission(s256)
    if new_state is MissionState.REVOKED:
        return control.revoke_mission(s256)
    if new_state is MissionState.COMPLETED:
        return control.complete_mission(s256)
    raise ValueError(f"PATCH not supported for target state: {new_state!r}")
