"""Mission-aware decision making for the Person Server (Layer 1).

The protocol gives the PS *correlation* — every token request and tool call references the
approved mission by ``s256``. The protocol does not give it *containment*: the spec does not
say whether a request is inside or outside the approved authority. That judgement lives
above the protocol, here at the PS.

A ``MissionEvaluator`` is consulted before the PS issues an auth token (and could equally be
consulted for permission requests). It is given the mission, the full mission log, and a
summary of the new request, and returns one of four decisions:

- ``allow``: request is within the mission's scope — issue the auth token, skip the consent
  prompt even if scope normally requires one. Logged to the mission log.
- ``escalate``: boundary case — fall through to the normal user consent flow, with the
  evaluator's reason shown to the user.
- ``clarify``: not enough information to decide — return ``AAuth-Requirement: clarification``
  to the agent with a question.
- ``deny``: clearly outside the mission's bounds — fail the request and log it.

This is the place where Karl McGuinness's containment / authority-model thinking lives in
this server.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Protocol, runtime_checkable

from ps.models import Mission, MissionLogEntry


@dataclass(frozen=True, slots=True)
class TokenRequestSummary:
    """The slice of a token request the evaluator needs.

    Kept narrow on purpose — evaluators must not depend on transport-level details.
    """

    agent_id: str
    resource_iss: str | None
    resource_scope: str | None
    justification: str | None
    upstream_token_present: bool = False


Decision = Literal["allow", "escalate", "clarify", "deny"]


@dataclass(frozen=True, slots=True)
class EvaluationDecision:
    """Outcome of a mission evaluation."""

    decision: Decision
    reason: str
    #: Question to send back to the agent when ``decision == "clarify"``.
    clarification_question: str | None = None

    @staticmethod
    def allow(reason: str) -> EvaluationDecision:
        return EvaluationDecision(decision="allow", reason=reason)

    @staticmethod
    def escalate(reason: str) -> EvaluationDecision:
        return EvaluationDecision(decision="escalate", reason=reason)

    @staticmethod
    def clarify(question: str, reason: str = "") -> EvaluationDecision:
        return EvaluationDecision(
            decision="clarify",
            reason=reason or question,
            clarification_question=question,
        )

    @staticmethod
    def deny(reason: str) -> EvaluationDecision:
        return EvaluationDecision(decision="deny", reason=reason)


@runtime_checkable
class MissionEvaluator(Protocol):
    """Port for the PS-side mission-aware decision policy."""

    def evaluate(
        self,
        mission: Mission,
        log: list[MissionLogEntry],
        request: TokenRequestSummary,
    ) -> EvaluationDecision: ...


class NoopMissionEvaluator:
    """Default: always escalate to the standard consent flow.

    Use this when no Layer 1 policy is configured. Behavior matches the pre-Layer-1 server.
    """

    def evaluate(
        self,
        mission: Mission,
        log: list[MissionLogEntry],
        request: TokenRequestSummary,
    ) -> EvaluationDecision:
        return EvaluationDecision.escalate("no evaluator configured")
