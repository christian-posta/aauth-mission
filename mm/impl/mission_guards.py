"""Validate MissionRef against backend state."""

from __future__ import annotations

from mm.exceptions import MissionTerminatedError, NotFoundError
from mm.impl.backend import MMBackend
from mm.models import Mission, MissionRef, MissionState


def require_active_mission(backend: MMBackend, ref: MissionRef) -> Mission:
    m = backend.missions.get(ref.s256)
    if m is None:
        raise NotFoundError("unknown mission")
    if m.approver.rstrip("/") != ref.approver.rstrip("/"):
        raise NotFoundError("unknown mission")
    if m.state != MissionState.ACTIVE:
        raise MissionTerminatedError()
    return m
