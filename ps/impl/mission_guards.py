"""Validate MissionRef against backend state."""

from __future__ import annotations

from ps.exceptions import MissionTerminatedError, NotFoundError
from ps.impl.mission_state import MissionStatePort
from ps.models import Mission, MissionRef, MissionState


def require_active_mission(mission: MissionStatePort, ref: MissionRef) -> Mission:
    m = mission.get_mission(ref.s256)
    if m is None:
        raise NotFoundError("unknown mission")
    if m.approver.rstrip("/") != ref.approver.rstrip("/"):
        raise NotFoundError("unknown mission")
    if m.state != MissionState.ACTIVE:
        raise MissionTerminatedError()
    return m
