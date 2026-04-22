"""Admin mission control: GET/PATCH /missions."""

from __future__ import annotations

from ps.models import Mission, MissionState
from ps.service.mission_control import MissionControl


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
    """PATCH `/missions/{s256}` with body `{ "state": "terminated" }`."""
    if new_state is MissionState.TERMINATED:
        return control.terminate_mission(s256)
    raise ValueError(f"PATCH only supports target state terminated, got: {new_state!r}")
