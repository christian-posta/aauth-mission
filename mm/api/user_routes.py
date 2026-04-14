"""User / consent routes (HTTP adapter for UserConsent)."""

from __future__ import annotations

from mm.models import ConsentContext, DecisionResult, UserDecision
from mm.service.user_consent import UserConsent


def get_interaction_route(consent: UserConsent, code: str) -> ConsentContext:
    """Resolve interaction code (used by GET `/consent` and legacy GET `/interaction`)."""
    return consent.get_consent_context(code)


def post_decision_route(consent: UserConsent, pending_id: str, decision: UserDecision) -> DecisionResult:
    """POST consent decision (used by `/consent/.../decision` and legacy `/interaction/.../decision`)."""
    return consent.record_decision(pending_id, decision)
