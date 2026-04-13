"""Agent-facing routes: POST /mission, POST /token, GET/POST/DELETE /pending/{id}.

HTTP message signatures and agent token validation belong in the framework adapter.
"""

from __future__ import annotations

from dataclasses import dataclass

from mm.models import MissionOutcome, MissionProposal, PendingPollOutcome, TokenOutcome, TokenRequest
from mm.service.mission_lifecycle import MissionLifecycle
from mm.service.token_broker import TokenBroker


def create_mission_route(lifecycle: MissionLifecycle, proposal: MissionProposal) -> MissionOutcome:
    """POST `/mission` — signed body contains `mission_proposal` (mapped to `proposal_text`)."""
    return lifecycle.create_mission(proposal)


def request_token_route(broker: TokenBroker, request: TokenRequest) -> TokenOutcome:
    """POST `/token`."""
    return broker.request_token(request)


def get_pending_route(broker: TokenBroker, pending_id: str, agent_id: str) -> PendingPollOutcome:
    """GET `/pending/{pending_id}`."""
    return broker.get_pending(pending_id, agent_id)


@dataclass(frozen=True, slots=True)
class ClarificationPostBody:
    clarification_response: str


@dataclass(frozen=True, slots=True)
class UpdatedTokenPostBody:
    resource_token: str
    justification: str | None = None


def post_pending_route(
    broker: TokenBroker,
    pending_id: str,
    agent_id: str,
    body: ClarificationPostBody | UpdatedTokenPostBody,
) -> TokenOutcome:
    """POST `/pending/{pending_id}` — dispatch by body shape (protocol §Agent Response to Clarification)."""
    if isinstance(body, ClarificationPostBody):
        return broker.post_clarification_response(pending_id, agent_id, body.clarification_response)
    return broker.post_updated_request(pending_id, agent_id, body.resource_token, body.justification)


def cancel_pending_route(broker: TokenBroker, pending_id: str, agent_id: str) -> None:
    """DELETE `/pending/{pending_id}`."""
    broker.cancel_request(pending_id, agent_id)
