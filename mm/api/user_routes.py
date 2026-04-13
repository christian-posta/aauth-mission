"""User / consent routes: GET /interaction, POST /interaction/{id}/decision."""

from __future__ import annotations

from mm.models import ConsentContext, DecisionResult, UserDecision
from mm.service.user_consent import UserConsent


def get_interaction_route(consent: UserConsent, code: str) -> ConsentContext:
    """GET `/interaction?code=...`."""
    return consent.get_consent_context(code)


def post_decision_route(consent: UserConsent, pending_id: str, decision: UserDecision) -> DecisionResult:
    """POST `/interaction/{pending_id}/decision`."""
    return consent.record_decision(pending_id, decision)
