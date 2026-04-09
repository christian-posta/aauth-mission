"""In-memory TokenBroker backed by MemoryPendingStore and ASFederator."""

from __future__ import annotations

from mm.exceptions import NotFoundError
from mm.federation.as_federator import ASFederator
from mm.impl.memory_pending import MemoryPendingStore
from mm.models import (
    AuthTokenResponse,
    DeferredResponse,
    Mission,
    PendingStatus,
    RequirementLevel,
    TokenOutcome,
    TokenRequest,
)
from mm.service.token_broker import TokenBroker


class MemoryTokenBroker(TokenBroker):
    def __init__(
        self,
        store: MemoryPendingStore,
        federator: ASFederator,
        *,
        agent_jwt_stub: str,
        auto_approve_without_consent: bool = False,
    ) -> None:
        self._store = store
        self._federator = federator
        self._agent_jwt_stub = agent_jwt_stub
        self._auto = auto_approve_without_consent

    def request_token(self, request: TokenRequest) -> TokenOutcome:
        if self._auto:
            return self._federator.request_auth_token(
                request.resource_token,
                self._agent_jwt_stub,
                request.upstream_token,
            )
        pid = self._store.create_pending(request)
        self._store.update_pending(pid, requirement=RequirementLevel.INTERACTION)
        return self._store.get_pending(pid)  # type: ignore[return-value]

    def get_pending(self, pending_id: str) -> AuthTokenResponse | DeferredResponse:
        val = self._store.get_pending(pending_id)
        if isinstance(val, Mission):
            raise NotFoundError("pending id refers to a mission, not token")
        return val

    def post_clarification_response(self, pending_id: str, response_text: str) -> DeferredResponse:
        _ = response_text
        self._store.update_pending(
            pending_id,
            requirement=RequirementLevel.INTERACTION,
            clarification=None,
            status=PendingStatus.PENDING,
        )
        out = self._store.get_pending(pending_id)
        if isinstance(out, DeferredResponse):
            return out
        raise RuntimeError("unexpected terminal state after clarification")

    def post_updated_request(
        self,
        pending_id: str,
        new_resource_token: str,
        justification: str | None,
    ) -> DeferredResponse:
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
        out = self._store.get_pending(pending_id)
        if isinstance(out, DeferredResponse):
            return out
        raise RuntimeError("unexpected terminal state after updated request")

    def cancel_request(self, pending_id: str) -> None:
        self._store.delete_pending(pending_id)
