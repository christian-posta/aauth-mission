"""Mutable in-memory state shared by MM service implementations."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

from mm.models import (
    AuthTokenResponse,
    Mission,
    MissionProposal,
    MissionState,
    PendingStatus,
    RequirementLevel,
    TokenRequest,
)


@dataclass
class PendingRecord:
    pending_id: str
    interaction_code: str
    kind: Literal["token", "mission"]
    token_request: TokenRequest | None = None
    mission_proposal: MissionProposal | None = None
    owner_id: str | None = None
    status: PendingStatus = PendingStatus.PENDING
    requirement: RequirementLevel | None = None
    clarification: str | None = None
    timeout: int | None = None
    options: list[str] | None = None
    terminal: AuthTokenResponse | Mission | None = None
    failure: str | None = None
    gone: bool = False


@dataclass
class MMBackend:
    missions: dict[str, Mission] = field(default_factory=dict)
    pending: dict[str, PendingRecord] = field(default_factory=dict)
    code_index: dict[str, str] = field(default_factory=dict)  # interaction code -> pending_id


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
