"""In-memory PendingRequestStore."""

from __future__ import annotations

import secrets

from mm.exceptions import PendingDeniedError, PendingGoneError
from mm.impl.backend import MMBackend, PendingRecord
from mm.models import (
    AuthTokenResponse,
    DeferredResponse,
    Mission,
    MissionProposal,
    PendingStatus,
    PendingStoreValue,
    RequirementLevel,
    TokenRequest,
)
from mm.service.pending_store import PendingRequestStore


def _pending_path(pending_id: str) -> str:
    return f"/pending/{pending_id}"


class MemoryPendingStore(PendingRequestStore):
    """If set, included on deferred responses when `requirement=interaction`."""

    def __init__(self, backend: MMBackend, interaction_base_url: str) -> None:
        self._b = backend
        self._interaction_base_url = interaction_base_url.rstrip("/")

    def create_pending(self, original_request: TokenRequest | MissionProposal) -> str:
        pending_id = secrets.token_urlsafe(12).replace("-", "")[:16]
        code = secrets.token_urlsafe(16)
        if isinstance(original_request, TokenRequest):
            rec = PendingRecord(
                pending_id=pending_id,
                interaction_code=code,
                kind="token",
                token_request=original_request,
            )
        else:
            rec = PendingRecord(
                pending_id=pending_id,
                interaction_code=code,
                kind="mission",
                mission_proposal=original_request,
            )
        self._b.pending[pending_id] = rec
        self._b.code_index[code] = pending_id
        return pending_id

    def _require(self, pending_id: str) -> PendingRecord:
        rec = self._b.pending.get(pending_id)
        if rec is None:
            from mm.exceptions import NotFoundError

            raise NotFoundError("unknown pending id")
        return rec

    def get_pending(self, pending_id: str) -> PendingStoreValue:
        rec = self._require(pending_id)
        if rec.gone:
            raise PendingGoneError()
        if rec.failure:
            raise PendingDeniedError(rec.failure)
        if rec.terminal is not None:
            return rec.terminal
        return self._to_deferred(rec)

    def get_interaction_code(self, pending_id: str) -> str:
        return self._require(pending_id).interaction_code

    def replace_token_request(
        self,
        pending_id: str,
        *,
        resource_token: str,
        justification: str | None,
    ) -> None:
        rec = self._require(pending_id)
        if rec.token_request is None:
            raise ValueError("not a token pending")
        from dataclasses import replace

        rec.token_request = replace(
            rec.token_request,
            resource_token=resource_token,
            justification=justification,
        )

    def _to_deferred(self, rec: PendingRecord) -> DeferredResponse:
        interaction_url: str | None = None
        show_code: str | None = None
        if rec.requirement == RequirementLevel.INTERACTION:
            interaction_url = f"{self._interaction_base_url}/interaction"
            show_code = rec.interaction_code
        return DeferredResponse(
            pending_id=rec.pending_id,
            pending_url=_pending_path(rec.pending_id),
            retry_after=0,
            requirement=rec.requirement,
            interaction_url=interaction_url,
            code=show_code,
            clarification=rec.clarification,
            timeout=rec.timeout,
            options=rec.options,
            status=rec.status,
        )

    def update_pending(
        self,
        pending_id: str,
        *,
        status: PendingStatus | None = None,
        requirement: RequirementLevel | None = None,
        clarification: str | None = None,
        timeout: int | None = None,
        options: list[str] | None = None,
    ) -> None:
        rec = self._require(pending_id)
        if status is not None:
            rec.status = status
        if requirement is not None:
            rec.requirement = requirement
        if clarification is not None:
            rec.clarification = clarification
        if timeout is not None:
            rec.timeout = timeout
        if options is not None:
            rec.options = options

    def resolve_pending(self, pending_id: str, result: AuthTokenResponse | Mission) -> None:
        rec = self._require(pending_id)
        rec.terminal = result
        rec.failure = None

    def fail_pending(self, pending_id: str, error: str) -> None:
        rec = self._require(pending_id)
        rec.failure = error
        rec.terminal = None

    def delete_pending(self, pending_id: str) -> None:
        rec = self._require(pending_id)
        rec.gone = True
        rec.terminal = None

    def lookup_code(self, code: str) -> PendingRecord:
        pid = self._b.code_index.get(code)
        if pid is None:
            from mm.exceptions import NotFoundError

            raise NotFoundError("unknown interaction code")
        return self._require(pid)

    def get_record(self, pending_id: str) -> PendingRecord:
        """Implementation helper — pending record including internal fields."""
        return self._require(pending_id)
