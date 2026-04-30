"""In-memory PendingRequestStore."""

from __future__ import annotations

import secrets
import time
from typing import Any

from ps.exceptions import (
    InvalidInteractionCodeError,
    NotFoundError,
    PendingDeniedError,
    PendingExpiredError,
    PendingGoneError,
    SlowDownError,
)
from ps.impl.backend import PSBackend, PendingRecord, utc_now
from ps.models import (
    AuthTokenResponse,
    DeferredResponse,
    InteractionTerminalResult,
    Mission,
    MissionProposal,
    PendingStatus,
    PendingStoreValue,
    RequirementLevel,
    TokenRequest,
)
from ps.service.pending_store import PendingRequestStore

# Minimum interval between polls (seconds); below this returns 429 slow_down per spec backoff guidance.
_MIN_POLL_INTERVAL = 0.05

# Deferred 202 responses must not advertise Retry-After: 0 while the above limit applies:
# clients (e.g. aauth.async_poll_pending_url) skip sleep when retry_after is 0 and poll
# immediately, which violates _MIN_POLL_INTERVAL and yields 429 on the next GET.
_DEFAULT_DEFERRED_RETRY_AFTER = 1


def _pending_path(pending_id: str, base_url: str) -> str:
    """Build absolute pending URL per SPEC (agents need full URL for polling)."""
    return f"{base_url.rstrip('/')}/pending/{pending_id}"


# Human consent entry (browser). Loads `/ui/consent.html?code=...`; that page calls `GET /consent?code=...`.
CONSENT_UI_PATH = "/ui/consent.html"


class MemoryPendingStore(PendingRequestStore):
    """If set, included on deferred responses when `requirement=interaction`."""

    def __init__(
        self,
        backend: PSBackend,
        interaction_base_url: str,
        *,
        default_ttl_seconds: int = 600,
    ) -> None:
        self._b = backend
        self._interaction_base_url = interaction_base_url.rstrip("/")
        self._default_ttl_seconds = default_ttl_seconds

    @property
    def interaction_base_url(self) -> str:
        return self._interaction_base_url

    def _owner_for_token_request(self, req: TokenRequest) -> str | None:
        for m in self._b.iter_missions():
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
                ttl_seconds=self._default_ttl_seconds,
                token_request=original_request,
                owner_id=owner_id,
            )
        else:
            rec = PendingRecord(
                pending_id=pending_id,
                interaction_code=code,
                kind="mission",
                ttl_seconds=self._default_ttl_seconds,
                mission_proposal=original_request,
                owner_id=original_request.owner_hint,
            )
        self._b.pending[pending_id] = rec
        self._b.code_index[code] = pending_id
        return pending_id

    def create_interaction_pending(
        self,
        *,
        agent_id: str,
        interaction_type: str,
        owner_id: str | None,
        mission_s256: str | None,
        summary: str | None = None,
        question: str | None = None,
        relay_url: str | None = None,
        relay_code: str | None = None,
        description: str | None = None,
    ) -> str:
        """Deferred user step for POST /interaction (agent-facing)."""
        pending_id = secrets.token_urlsafe(12).replace("-", "")[:16]
        code = secrets.token_urlsafe(16)
        rec = PendingRecord(
            pending_id=pending_id,
            interaction_code=code,
            kind="interaction",
            ttl_seconds=self._default_ttl_seconds,
            owner_id=owner_id,
            pending_agent_id=agent_id,
            interaction_type=interaction_type,
            interaction_summary=summary,
            interaction_question=question,
            relay_url=relay_url,
            relay_code=relay_code,
            mission_s256=mission_s256,
            interaction_description=description,
        )
        self._b.pending[pending_id] = rec
        self._b.code_index[code] = pending_id
        return pending_id

    def _require(self, pending_id: str) -> PendingRecord:
        rec = self._b.pending.get(pending_id)
        if rec is None:
            raise NotFoundError("unknown pending id")
        return rec

    def assert_agent_owns_pending(self, pending_id: str, agent_id: str) -> None:
        """Reject with 404 if the pending row is not for this agent (do not leak existence)."""
        try:
            rec = self._require(pending_id)
        except NotFoundError:
            raise
        aid: str | None = None
        if rec.token_request is not None:
            aid = rec.token_request.agent_id
        elif rec.mission_proposal is not None:
            aid = rec.mission_proposal.agent_id
        elif rec.pending_agent_id is not None:
            aid = rec.pending_agent_id
        else:
            aid = None
        if aid is None or aid != agent_id:
            raise NotFoundError("unknown pending id")

    def _check_ttl(self, rec: PendingRecord) -> None:
        if rec.terminal is not None or rec.gone or rec.failure:
            return
        elapsed = (utc_now() - rec.created_at).total_seconds()
        if elapsed <= rec.ttl_seconds:
            return
        if rec.status == PendingStatus.INTERACTING:
            self.fail_pending(rec.pending_id, "abandoned")
        else:
            self.fail_pending(rec.pending_id, "expired")

    def _rate_limit_poll(self, rec: PendingRecord) -> None:
        now = time.monotonic()
        if rec.last_poll_monotonic is not None:
            if now - rec.last_poll_monotonic < _MIN_POLL_INTERVAL:
                raise SlowDownError()
        rec.last_poll_monotonic = now

    def get_pending(self, pending_id: str, *, for_poll: bool = False) -> PendingStoreValue:
        rec = self._require(pending_id)
        self._check_ttl(rec)
        if rec.gone:
            raise PendingGoneError()
        if rec.failure:
            if rec.failure == "expired":
                raise PendingExpiredError()
            raise PendingDeniedError(rec.failure)
        if rec.terminal is not None:
            if rec.delivered:
                raise NotFoundError("unknown pending id")
            rec.delivered = True
            return rec.terminal
        if for_poll:
            self._rate_limit_poll(rec)
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
            pending_url=_pending_path(rec.pending_id, self._interaction_base_url),
            retry_after=_DEFAULT_DEFERRED_RETRY_AFTER,
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

    def set_callback_url(self, pending_id: str, callback_url: str | None) -> None:
        rec = self._require(pending_id)
        rec.callback_url = callback_url

    def resolve_pending(
        self, pending_id: str, result: AuthTokenResponse | Mission | InteractionTerminalResult
    ) -> None:
        rec = self._require(pending_id)
        rec.terminal = result
        rec.failure = None
        self._invalidate_code_for(pending_id)

    def fail_pending(self, pending_id: str, error: str) -> None:
        rec = self._require(pending_id)
        rec.failure = error
        rec.terminal = None
        self._invalidate_code_for(pending_id)

    def delete_pending(self, pending_id: str) -> None:
        rec = self._require(pending_id)
        rec.gone = True
        rec.terminal = None
        self._invalidate_code_for(pending_id)

    def lookup_code(self, code: str) -> PendingRecord:
        pid = self._b.code_index.get(code)
        if pid is None:
            raise InvalidInteractionCodeError()
        rec = self._require(pid)
        # Check TTL; this may mark the row as expired/failed without raising yet.
        self._check_ttl(rec)
        if rec.gone or rec.failure or rec.terminal is not None:
            # Row has terminated — remove stale code entry and reject.
            self._b.code_index.pop(code, None)
            raise InvalidInteractionCodeError()
        return rec

    def _invalidate_code_for(self, pending_id: str) -> None:
        """Remove code_index entry when a pending row reaches a terminal state."""
        rec = self._b.pending.get(pending_id)
        if rec is not None:
            self._b.code_index.pop(rec.interaction_code, None)

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
            elif rec.pending_agent_id is not None:
                agent_id = rec.pending_agent_id
            req_val = rec.requirement.value if rec.requirement is not None else None
            st_val = rec.status.value
            code = rec.interaction_code if rec.requirement == RequirementLevel.INTERACTION else None
            vclaims = rec.verified_resource_claims or {}
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
                    "pending_url": _pending_path(rec.pending_id, self.interaction_base_url),
                    "justification": rec.token_request.justification if rec.token_request else None,
                    "resource_iss": vclaims.get("iss") if vclaims else None,
                    "resource_scope": vclaims.get("scope") if vclaims else None,
                }
            )
        return sorted(out, key=lambda r: r["pending_id"])
