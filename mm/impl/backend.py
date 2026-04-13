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


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class PendingRecord:
    pending_id: str
    interaction_code: str
    kind: Literal["token", "mission"]
    created_at: datetime = field(default_factory=utc_now)
    ttl_seconds: int = 600
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
    delivered: bool = False
    clarification_responses: list[str] = field(default_factory=list)
    clarification_round: int = 0
    callback_url: str | None = None
    last_poll_monotonic: float | None = None


@dataclass
class MMBackend:
    missions: dict[str, Mission] = field(default_factory=dict)
    pending: dict[str, PendingRecord] = field(default_factory=dict)
    code_index: dict[str, str] = field(default_factory=dict)  # interaction code -> pending_id
