"""In-memory TokenBroker backed by MemoryPendingStore and ASFederator."""

from __future__ import annotations

from ps.exceptions import ClarificationLimitError, NotFoundError
from ps.federation.as_federator import ASFederator
from ps.impl.backend import PSBackend, utc_now
from ps.impl.memory_pending import MemoryPendingStore
from ps.impl.mission_guards import require_active_mission
from ps.models import (
    AuthTokenResponse,
    DeferredResponse,
    InteractionTerminalResult,
    Mission,
    MissionLogEntry,
    MissionLogKind,
    PendingStatus,
    RequirementLevel,
    TokenOutcome,
    TokenRequest,
)
from ps.service.token_broker import TokenBroker

_MAX_CLARIFICATION_ROUNDS = 5


class MemoryTokenBroker(TokenBroker):
    def __init__(
        self,
        store: MemoryPendingStore,
        federator: ASFederator,
        backend: PSBackend,
        *,
        agent_jwt_stub: str,
        auto_approve_without_consent: bool = False,
    ) -> None:
        self._store = store
        self._federator = federator
        self._b = backend
        self._agent_jwt_stub = agent_jwt_stub
        self._auto = auto_approve_without_consent

    def request_token(self, request: TokenRequest) -> TokenOutcome:
        if request.mission is not None:
            require_active_mission(self._b, request.mission)
        if self._auto:
            if request.mission is not None:
                require_active_mission(self._b, request.mission)
            return self._federator.request_auth_token(
                request.resource_token,
                self._agent_jwt_stub,
                request.upstream_token,
            )
        pid = self._store.create_pending(request)
        self._store.update_pending(pid, requirement=RequirementLevel.INTERACTION)
        val = self._store.get_pending(pid, for_poll=False)
        if isinstance(val, Mission):
            raise NotFoundError("unexpected mission outcome on token request")
        return val  # DeferredResponse

    def get_pending(self, pending_id: str, agent_id: str) -> AuthTokenResponse | DeferredResponse | InteractionTerminalResult:
        self._store.assert_agent_owns_pending(pending_id, agent_id)
        val = self._store.get_pending(pending_id, for_poll=True)
        if isinstance(val, Mission):
            raise NotFoundError("pending id refers to a mission, not token")
        return val

    def post_clarification_response(self, pending_id: str, agent_id: str, response_text: str) -> DeferredResponse:
        self._store.assert_agent_owns_pending(pending_id, agent_id)
        rec = self._store.get_record(pending_id)
        if rec.clarification_round >= _MAX_CLARIFICATION_ROUNDS:
            raise ClarificationLimitError()
        rec.clarification_responses.append(response_text)
        rec.clarification_round += 1
        if rec.token_request and rec.token_request.mission:
            self._b.append_mission_log(
                rec.token_request.mission.s256,
                MissionLogEntry(
                    ts=utc_now(),
                    kind=MissionLogKind.CLARIFICATION,
                    payload={"response": response_text},
                ),
            )
        self._store.update_pending(
            pending_id,
            requirement=RequirementLevel.INTERACTION,
            clarification=None,
            status=PendingStatus.PENDING,
        )
        out = self._store.get_pending(pending_id, for_poll=False)
        if isinstance(out, DeferredResponse):
            return out
        raise RuntimeError("unexpected terminal state after clarification")

    def post_updated_request(
        self,
        pending_id: str,
        agent_id: str,
        new_resource_token: str,
        justification: str | None,
    ) -> DeferredResponse:
        self._store.assert_agent_owns_pending(pending_id, agent_id)
        self._store.replace_token_request(
            pending_id,
            resource_token=new_resource_token,
            justification=justification,
        )
        self._store.update_pending(
            pending_id,
            requirement=RequirementLevel.INTERACTION,
            status=PendingStatus.PENDING,
        )
        out = self._store.get_pending(pending_id, for_poll=False)
        if isinstance(out, DeferredResponse):
            return out
        raise RuntimeError("unexpected terminal state after updated request")

    def cancel_request(self, pending_id: str, agent_id: str) -> None:
        self._store.assert_agent_owns_pending(pending_id, agent_id)
        self._store.delete_pending(pending_id)
