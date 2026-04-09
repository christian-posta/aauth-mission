"""Shared enums and dataclasses for the AAuth Mission Manager (draft-hardt-aauth-protocol)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Union


class MissionState(str, Enum):
    """Mission lifecycle states (protocol §Mission Management)."""

    PROPOSED = "proposed"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    COMPLETED = "completed"
    REVOKED = "revoked"
    EXPIRED = "expired"


class RequirementLevel(str, Enum):
    """AAuth-Requirement `requirement` values (protocol §Requirement Levels)."""

    INTERACTION = "interaction"
    APPROVAL = "approval"
    AUTH_TOKEN = "auth-token"
    CLARIFICATION = "clarification"
    CLAIMS = "claims"


class PendingStatus(str, Enum):
    """Deferred response body `status` (protocol §Pending Response)."""

    PENDING = "pending"
    INTERACTING = "interacting"


@dataclass(frozen=True, slots=True)
class Mission:
    s256: str
    approved_text: str
    state: MissionState
    agent_id: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class MissionProposal:
    agent_id: str
    proposal_text: str


@dataclass(frozen=True, slots=True)
class TokenRequest:
    agent_id: str
    resource_token: str
    justification: str | None = None
    upstream_token: str | None = None
    login_hint: str | None = None
    tenant: str | None = None
    domain_hint: str | None = None


@dataclass(frozen=True, slots=True)
class AuthTokenResponse:
    auth_token: str
    expires_in: int


@dataclass(frozen=True, slots=True)
class DeferredResponse:
    pending_id: str
    pending_url: str
    retry_after: int
    requirement: RequirementLevel | None = None
    interaction_url: str | None = None
    code: str | None = None
    clarification: str | None = None
    timeout: int | None = None
    options: list[str] | None = None
    status: PendingStatus = PendingStatus.PENDING


@dataclass(frozen=True, slots=True)
class ConsentContext:
    pending_id: str
    resource_name: str | None = None
    scopes: dict[str, str] = field(default_factory=dict)
    justification: str | None = None
    mission: Mission | None = None
    agent_name: str | None = None


@dataclass(frozen=True, slots=True)
class UserDecision:
    approved: bool
    clarification_question: str | None = None


@dataclass(frozen=True, slots=True)
class ASMetadata:
    issuer: str
    token_endpoint: str
    jwks_uri: str


@dataclass(frozen=True, slots=True)
class ClaimsRequest:
    required_claims: list[str]
    pending_url: str


@dataclass(frozen=True, slots=True)
class MMMetadata:
    manager: str
    token_endpoint: str
    mission_endpoint: str
    mission_control_endpoint: str | None
    jwks_uri: str


# Terminal or deferred outcomes for endpoints that may return 200 or 202.
MissionOutcome = Union[Mission, DeferredResponse]
TokenOutcome = Union[AuthTokenResponse, DeferredResponse]
PendingPollOutcome = Union[AuthTokenResponse, DeferredResponse]
PendingStoreValue = Union[DeferredResponse, AuthTokenResponse, Mission]
