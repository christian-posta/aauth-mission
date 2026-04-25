"""SQL-backed pending store (mirrors ps.impl.memory_pending)."""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from persistence.models import PsPendingRow
from persistence.serde import (
    compute_is_open,
    pending_record_from_dict,
    pending_record_to_dict,
    requirement_value,
)
from ps.exceptions import (
    InvalidInteractionCodeError,
    NotFoundError,
    PendingDeniedError,
    PendingExpiredError,
    PendingGoneError,
    SlowDownError,
)
from ps.impl.backend import PendingRecord, utc_now
from ps.impl.memory_pending import CONSENT_UI_PATH, _pending_path
from ps.impl.mission_state import MissionStatePort
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

_MIN_POLL_INTERVAL = 0.05


def _deferred(
    rec: PendingRecord, interaction_base_url: str) -> DeferredResponse:
    interaction_url: str | None = None
    show_code: str | None = None
    if rec.requirement == RequirementLevel.INTERACTION:
        interaction_url = f"{interaction_base_url}{CONSENT_UI_PATH}"
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


class DatabasePendingStore(PendingRequestStore):
    def __init__(
        self,
        session_factory: Callable[[], Session],
        mission: MissionStatePort,
        interaction_base_url: str,
        *,
        default_ttl_seconds: int = 600,
    ) -> None:
        self._session_factory = session_factory
        self._mission = mission
        self._interaction_base_url = interaction_base_url.rstrip("/")
        self._default_ttl_seconds = default_ttl_seconds

    @property
    def interaction_base_url(self) -> str:
        return self._interaction_base_url

    def _row_to_rec(self, row: PsPendingRow) -> PendingRecord:
        return pending_record_from_dict(row.data)

    def _load_row(self, pending_id: str) -> PsPendingRow | None:
        with self._session_factory() as s:
            return s.get(PsPendingRow, pending_id)

    def _load(self, pending_id: str) -> PendingRecord | None:
        r = self._load_row(pending_id)
        if r is None:
            return None
        return self._row_to_rec(r)

    def _save_rec(self, rec: PendingRecord) -> None:
        data = pending_record_to_dict(rec)
        is_open = compute_is_open(rec)
        reqv = requirement_value(rec)
        with self._session_factory() as s:
            row = s.get(PsPendingRow, rec.pending_id)
            if row is None:
                s.add(
                    PsPendingRow(
                        pending_id=rec.pending_id,
                        interaction_code=rec.interaction_code,
                        owner_id=rec.owner_id,
                        rec_kind=rec.kind,
                        requirement=reqv,
                        gone=rec.gone,
                        code_unusable=False,
                        is_open=is_open,
                        data=data,
                    )
                )
            else:
                row.interaction_code = rec.interaction_code
                row.owner_id = rec.owner_id
                row.rec_kind = rec.kind
                row.requirement = reqv
                row.gone = rec.gone
                row.is_open = is_open
                row.data = data
            s.commit()

    def _update_row_meta(self, pending_id: str, *, code_unusable: bool | None = None) -> None:
        with self._session_factory() as s:
            row = s.get(PsPendingRow, pending_id)
            if row is not None and code_unusable is not None:
                row.code_unusable = code_unusable
            s.commit()

    def _owner_for_token_request(self, req: TokenRequest) -> str | None:
        for m in self._mission.iter_missions():
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
        self._save_rec(rec)
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
        self._save_rec(rec)
        return pending_id

    def _require(self, pending_id: str) -> PendingRecord:
        rec = self._load(pending_id)
        if rec is None:
            raise NotFoundError("unknown pending id")
        return rec

    def assert_agent_owns_pending(self, pending_id: str, agent_id: str) -> None:
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
        self._save_rec(rec)

    def get_pending(self, pending_id: str, *, for_poll: bool = False) -> PendingStoreValue:
        rec0 = self._require(pending_id)
        self._check_ttl(rec0)
        rec = self._load(pending_id)
        if rec is None:
            raise NotFoundError("unknown pending id")
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
            self._save_rec(rec)
            return rec.terminal
        if for_poll:
            self._rate_limit_poll(self._require(pending_id))
            rec = self._load(pending_id) or rec
        return _deferred(rec, self._interaction_base_url)

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
        self._save_rec(rec)

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
        self._save_rec(rec)

    def set_callback_url(self, pending_id: str, callback_url: str | None) -> None:
        rec = self._require(pending_id)
        rec.callback_url = callback_url
        self._save_rec(rec)

    def resolve_pending(
        self, pending_id: str, result: AuthTokenResponse | Mission | InteractionTerminalResult
    ) -> None:
        rec = self._require(pending_id)
        rec.terminal = result
        rec.failure = None
        self._save_rec(rec)
        self._invalidate_code_for(pending_id)

    def fail_pending(self, pending_id: str, error: str) -> None:
        rec = self._require(pending_id)
        rec.failure = error
        rec.terminal = None
        self._save_rec(rec)
        self._invalidate_code_for(pending_id)

    def delete_pending(self, pending_id: str) -> None:
        rec = self._require(pending_id)
        rec.gone = True
        rec.terminal = None
        self._save_rec(rec)
        self._invalidate_code_for(pending_id)

    def _invalidate_code_for(self, pending_id: str) -> None:
        self._update_row_meta(pending_id, code_unusable=True)

    def lookup_code(self, code: str) -> PendingRecord:
        with self._session_factory() as s:
            row = s.execute(
                select(PsPendingRow).where(
                    PsPendingRow.interaction_code == code,
                    PsPendingRow.code_unusable.is_(False),
                )
            ).scalars().first()
        if row is None:
            raise InvalidInteractionCodeError()
        rec = self._row_to_rec(row)
        self._check_ttl(rec)
        rec2 = self._load(row.pending_id)
        if rec2 is None:
            raise InvalidInteractionCodeError()
        rec = rec2
        if rec.gone or rec.failure or rec.terminal is not None:
            with self._session_factory() as s:
                r2 = s.get(PsPendingRow, rec.pending_id)
                if r2 is not None:
                    r2.code_unusable = True
                    s.commit()
            raise InvalidInteractionCodeError()
        return rec

    def get_record(self, pending_id: str) -> PendingRecord:
        return self._require(pending_id)

    def list_interaction_pending_for_owner(self, owner_id: str) -> list[PendingRecord]:
        out: list[PendingRecord] = []
        with self._session_factory() as s:
            rows = s.execute(
                select(PsPendingRow).where(
                    PsPendingRow.is_open.is_(True),
                    PsPendingRow.owner_id == owner_id,
                    PsPendingRow.requirement == RequirementLevel.INTERACTION.value,
                )
            ).scalars().all()
        for row in rows:
            rec = self._row_to_rec(row)
            self._check_ttl(rec)
            rec2 = self._load(row.pending_id)
            if rec2 is None:
                continue
            if rec2.gone or rec2.terminal is not None:
                continue
            if rec2.requirement != RequirementLevel.INTERACTION:
                continue
            if rec2.owner_id != owner_id:
                continue
            out.append(rec2)
        return sorted(out, key=lambda r: r.pending_id)

    def list_open_pending_for_admin(self) -> list[dict[str, Any]]:
        with self._session_factory() as s:
            rows = s.execute(select(PsPendingRow).where(PsPendingRow.is_open.is_(True))).scalars().all()
        out: list[dict[str, Any]] = []
        for row in rows:
            rec = self._row_to_rec(row)
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
                    "interaction_url": f"{self._interaction_base_url}{CONSENT_UI_PATH}",
                    "pending_url": _pending_path(rec.pending_id),
                    "justification": rec.token_request.justification if rec.token_request else None,
                    "resource_iss": vclaims.get("iss") if vclaims else None,
                    "resource_scope": vclaims.get("scope") if vclaims else None,
                }
            )
        return sorted(out, key=lambda r: r["pending_id"])
