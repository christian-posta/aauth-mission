"""In-memory PendingRequestStore."""

from __future__ import annotations

import secrets
from typing import Any

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


# Human consent entry (browser). Loads `/ui/consent.html?code=...`; that page calls `GET /interaction?code=...`.
CONSENT_UI_PATH = "/ui/consent.html"


class MemoryPendingStore(PendingRequestStore):
    """If set, included on deferred responses when `requirement=interaction`."""

    def __init__(self, backend: MMBackend, interaction_base_url: str) -> None:
        self._b = backend
        self._interaction_base_url = interaction_base_url.rstrip("/")

    @property
    def interaction_base_url(self) -> str:
        return self._interaction_base_url

    def _owner_for_token_request(self, req: TokenRequest) -> str | None:
        for m in self._b.missions.values():
            if m.agent_id == req.agent_id and m.owner_id is not None:
                return m.owner_id
        return None

    def create_pending(self, original_request: TokenRequest | MissionProposal) -> str:
        pending_id = secrets.token_urlsafe(12).replace("-", "")[:16]
        code = secrets.token_urlsafe(16)
        if isinstance(original_request, TokenRequest):
            owner_id = self._owner_for_token_request(original_request)
            rec = PendingRecord(
                pending_id=pending_id,
                interaction_code=code,
                kind="token",
                token_request=original_request,
                owner_id=owner_id,
            )
        else:
            rec = PendingRecord(
                pending_id=pending_id,
                interaction_code=code,
                kind="mission",
                mission_proposal=original_request,
                owner_id=original_request.owner_hint,
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
            interaction_url = f"{self._interaction_base_url}{CONSENT_UI_PATH}"
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

    def list_interaction_pending_for_owner(self, owner_id: str) -> list[PendingRecord]:
        """Pending rows awaiting user interaction, scoped to legal owner."""
        out: list[PendingRecord] = []
        for rec in self._b.pending.values():
            if rec.gone or rec.terminal is not None:
                continue
            if rec.requirement != RequirementLevel.INTERACTION:
                continue
            if rec.owner_id != owner_id:
                continue
            out.append(rec)
        return sorted(out, key=lambda r: r.pending_id)

    def list_open_pending_for_admin(self) -> list[dict[str, Any]]:
        """All in-flight pending rows (not gone, not resolved, not failed)."""
        out: list[dict[str, Any]] = []
        for rec in self._b.pending.values():
            if rec.gone or rec.terminal is not None or rec.failure:
                continue
            agent_id = ""
            if rec.token_request is not None:
                agent_id = rec.token_request.agent_id
            elif rec.mission_proposal is not None:
                agent_id = rec.mission_proposal.agent_id
            req_val = rec.requirement.value if rec.requirement is not None else None
            st_val = rec.status.value
            code = rec.interaction_code if rec.requirement == RequirementLevel.INTERACTION else None
            out.append(
                {
                    "pending_id": rec.pending_id,
                    "kind": rec.kind,
                    "status": st_val,
                    "requirement": req_val,
                    "agent_id": agent_id,
                    "owner_id": rec.owner_id,
                    "code": code,
                    "interaction_url": f"{self.interaction_base_url}{CONSENT_UI_PATH}",
                    "pending_url": _pending_path(rec.pending_id),
                    "justification": rec.token_request.justification if rec.token_request else None,
                }
            )
        return sorted(out, key=lambda r: r["pending_id"])
