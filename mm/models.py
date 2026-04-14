"""Shared enums and dataclasses for the AAuth Mission Manager (SPEC.md aligned)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Literal, Union


class MissionState(str, Enum):
    """Mission lifecycle (SPEC §Mission Management): active or terminated."""

    ACTIVE = "active"
    TERMINATED = "terminated"


class MissionLogKind(str, Enum):
    """Categories for mission log entries."""

    MISSION_APPROVED = "mission_approved"
    TOKEN_REQUEST = "token_request"
    PERMISSION = "permission"
    AUDIT = "audit"
    AGENT_INTERACTION = "agent_interaction"
    CLARIFICATION = "clarification"


@dataclass(frozen=True, slots=True)
class MissionLogEntry:
    """Single ordered entry in the mission log."""

    ts: datetime
    kind: MissionLogKind
    payload: dict[str, Any]


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
class MissionRef:
    """Mission object in JSON bodies: approver URL + s256 (SPEC)."""

    approver: str
    s256: str


@dataclass(frozen=True, slots=True)
class Mission:
    """Approved mission: blob_bytes are the exact JSON bytes used for s256."""

    s256: str
    blob_bytes: bytes
    state: MissionState
    agent_id: str
    approved_at: datetime
    owner_id: str | None
    approver: str
    description: str
    approved_tools: tuple[dict[str, str], ...] | None
    capabilities: tuple[str, ...] | None


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """Proposed or approved tool (name + description)."""

    name: str
    description: str


@dataclass(frozen=True, slots=True)
class MissionProposal:
    agent_id: str
    description: str
    tools: tuple[ToolSpec, ...] = ()
    owner_hint: str | None = None


@dataclass(frozen=True, slots=True)
class TokenRequest:
    agent_id: str
    resource_token: str
    justification: str | None = None
    upstream_token: str | None = None
    login_hint: str | None = None
    tenant: str | None = None
    domain_hint: str | None = None
    mission: MissionRef | None = None


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
class InteractionTerminalResult:
    """Terminal payload when polling a pending URL for agent interaction / completion."""

    body: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ConsentContext:
    pending_id: str
    resource_name: str | None = None
    scopes: dict[str, str] = field(default_factory=dict)
    justification: str | None = None
    mission: Mission | None = None
    agent_name: str | None = None
    clarification_responses: tuple[str, ...] = ()
    interaction_type: str | None = None
    summary: str | None = None
    question: str | None = None


@dataclass(frozen=True, slots=True)
class UserDecision:
    approved: bool
    clarification_question: str | None = None
    answer_text: str | None = None


@dataclass(frozen=True, slots=True)
class DecisionResult:
    """Outcome of POST /consent/{pending_id}/decision."""

    redirect_url: str | None = None


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
    issuer: str
    token_endpoint: str
    mission_endpoint: str
    permission_endpoint: str | None
    audit_endpoint: str | None
    interaction_endpoint: str | None
    mission_control_endpoint: str | None
    jwks_uri: str


@dataclass(frozen=True, slots=True)
class PermissionRequest:
    action: str
    description: str | None
    parameters: dict[str, Any] | None
    mission: MissionRef | None
    agent_id: str


@dataclass(frozen=True, slots=True)
class PermissionOutcome:
    permission: Literal["granted", "denied"]
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class AuditRequest:
    mission: MissionRef
    action: str
    description: str | None
    parameters: dict[str, Any] | None
    result: dict[str, Any] | None
    agent_id: str


@dataclass(frozen=True, slots=True)
class AgentInteractionRequest:
    """POST /interaction (agent, signed)."""

    type: Literal["interaction", "payment", "question", "completion"]
    description: str | None
    url: str | None
    code: str | None
    question: str | None
    summary: str | None
    mission: MissionRef | None
    agent_id: str


# Terminal or deferred outcomes for endpoints that may return 200 or 202.
MissionOutcome = Union[Mission, DeferredResponse]
TokenOutcome = Union[AuthTokenResponse, DeferredResponse]
PendingPollOutcome = Union[AuthTokenResponse, DeferredResponse, InteractionTerminalResult]
PendingStoreValue = Union[DeferredResponse, AuthTokenResponse, Mission, InteractionTerminalResult]
