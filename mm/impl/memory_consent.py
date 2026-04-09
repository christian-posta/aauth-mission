"""In-memory UserConsent."""

from __future__ import annotations

from mm.exceptions import NotFoundError
from mm.federation.as_federator import ASFederator
from mm.impl.backend import MMBackend
from mm.impl.memory_pending import MemoryPendingStore
from mm.impl.mission_utils import mission_from_proposal
from mm.models import ConsentContext, DeferredResponse, PendingStatus, RequirementLevel, UserDecision
from mm.service.user_consent import UserConsent


class MemoryUserConsent(UserConsent):
    def __init__(
        self,
        backend: MMBackend,
        store: MemoryPendingStore,
        federator: ASFederator,
        *,
        agent_jwt_stub: str,
    ) -> None:
        self._b = backend
        self._store = store
        self._federator = federator
        self._agent_jwt_stub = agent_jwt_stub

    def get_consent_context(self, code: str) -> ConsentContext:
        rec = self._store.lookup_code(code)
        justification = rec.token_request.justification if rec.token_request else None
        mission = None
        if rec.mission_proposal:
            aid = rec.mission_proposal.agent_id
            for m in self._b.missions.values():
                if m.agent_id == aid:
                    mission = m
                    break
        return ConsentContext(
            pending_id=rec.pending_id,
            resource_name=None,
            scopes={},
            justification=justification,
            mission=mission,
            agent_name=None,
        )

    def record_decision(self, pending_id: str, decision: UserDecision) -> None:
        rec = self._store.get_record(pending_id)

        if decision.clarification_question:
            self._store.update_pending(
                pending_id,
                requirement=RequirementLevel.CLARIFICATION,
                clarification=decision.clarification_question,
                status=PendingStatus.INTERACTING,
            )
            return
        if not decision.approved:
            self._store.fail_pending(pending_id, "user_denied")
            return
        if rec.kind == "token" and rec.token_request is not None:
            auth = self._federator.request_auth_token(
                rec.token_request.resource_token,
                self._agent_jwt_stub,
                rec.token_request.upstream_token,
            )
            if isinstance(auth, DeferredResponse):
                raise RuntimeError("federator unexpectedly deferred")
            self._store.resolve_pending(pending_id, auth)
            return
        if rec.kind == "mission" and rec.mission_proposal is not None:
            m = mission_from_proposal(rec.mission_proposal)
            self._b.missions[m.s256] = m
            self._store.resolve_pending(pending_id, m)
            return
        raise NotFoundError("invalid pending record")

    def mark_interacting(self, pending_id: str) -> None:
        self._store.update_pending(pending_id, status=PendingStatus.INTERACTING)
