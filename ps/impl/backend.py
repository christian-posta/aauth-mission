"""Mutable in-memory state shared by Person Server service implementations."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from ps.models import (
    AuthTokenResponse,
    InteractionTerminalResult,
    Mission,
    MissionLogEntry,
    MissionProposal,
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
    kind: Literal["token", "mission", "interaction"]
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
    terminal: AuthTokenResponse | Mission | InteractionTerminalResult | None = None
    # Agent-facing interaction pending (POST /interaction)
    interaction_type: str | None = None
    interaction_summary: str | None = None
    interaction_question: str | None = None
    relay_url: str | None = None
    relay_code: str | None = None
    mission_s256: str | None = None
    pending_agent_id: str | None = None
    interaction_description: str | None = None
    failure: str | None = None
    gone: bool = False
    delivered: bool = False
    clarification_responses: list[str] = field(default_factory=list)
    clarification_round: int = 0
    callback_url: str | None = None
    last_poll_monotonic: float | None = None
    #: Verified resource token claims (secure token requests only).
    verified_resource_claims: dict[str, Any] | None = None
    #: Ephemeral public JWK bound in the agent token (secure ``POST /token``).
    token_agent_cnf_jwk: dict[str, Any] | None = None


@dataclass
class PSBackend:
    missions: dict[str, Mission] = field(default_factory=dict)
    mission_log: dict[str, list[MissionLogEntry]] = field(default_factory=dict)
    pending: dict[str, PendingRecord] = field(default_factory=dict)
    code_index: dict[str, str] = field(default_factory=dict)  # interaction code -> pending_id

    def append_mission_log(self, s256: str, entry: MissionLogEntry) -> None:
        self.mission_log.setdefault(s256, []).append(entry)
