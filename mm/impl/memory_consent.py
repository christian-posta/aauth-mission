"""In-memory UserConsent."""

from __future__ import annotations

from dataclasses import replace

from mm.exceptions import NotFoundError
from mm.federation.as_federator import ASFederator
from mm.impl.backend import MMBackend, utc_now
from mm.impl.memory_pending import MemoryPendingStore
from mm.impl.mission_utils import mission_from_proposal
from mm.models import (
    AuthTokenResponse,
    ConsentContext,
    DecisionResult,
    DeferredResponse,
    InteractionTerminalResult,
    Mission,
    MissionLogEntry,
    MissionLogKind,
    MissionState,
    PendingStatus,
    RequirementLevel,
    UserDecision,
)
from mm.service.user_consent import UserConsent


class MemoryUserConsent(UserConsent):
    def __init__(
        self,
        backend: MMBackend,
        store: MemoryPendingStore,
        federator: ASFederator,
        *,
        agent_jwt_stub: str,
        ps_issuer: str,
    ) -> None:
        self._b = backend
        self._store = store
        self._federator = federator
        self._agent_jwt_stub = agent_jwt_stub
        self._ps_issuer = ps_issuer.rstrip("/")

    def _record_mission(self, m: Mission) -> None:
        self._b.missions[m.s256] = m
        self._b.append_mission_log(
            m.s256,
            MissionLogEntry(ts=utc_now(), kind=MissionLogKind.MISSION_APPROVED, payload={"agent_id": m.agent_id}),
        )

    def get_consent_context(self, code: str) -> ConsentContext:
        rec = self._store.lookup_code(code)
        justification = rec.token_request.justification if rec.token_request else None
        mission = None
        if rec.kind == "mission" and rec.mission_proposal:
            aid = rec.mission_proposal.agent_id
            for m in self._b.missions.values():
                if m.agent_id == aid:
                    mission = m
                    break
        elif rec.kind == "interaction" and rec.mission_s256:
            mission = self._b.missions.get(rec.mission_s256)
        responses = tuple(rec.clarification_responses) if rec.clarification_responses else ()
        if rec.kind == "interaction":
            return ConsentContext(
                pending_id=rec.pending_id,
                resource_name=None,
                scopes={},
                justification=rec.interaction_description,
                mission=mission,
                agent_name=None,
                clarification_responses=responses,
                interaction_type=rec.interaction_type,
                summary=rec.interaction_summary,
                question=rec.interaction_question,
            )
        return ConsentContext(
            pending_id=rec.pending_id,
            resource_name=None,
            scopes={},
            justification=justification,
            mission=mission,
            agent_name=None,
            clarification_responses=responses,
        )

    def record_decision(self, pending_id: str, decision: UserDecision) -> DecisionResult:
        rec = self._store.get_record(pending_id)

        if decision.clarification_question:
            self._store.update_pending(
                pending_id,
                requirement=RequirementLevel.CLARIFICATION,
                clarification=decision.clarification_question,
                status=PendingStatus.INTERACTING,
            )
            return DecisionResult(redirect_url=None)

        if not decision.approved:
            self._store.fail_pending(pending_id, "denied")
            return DecisionResult(redirect_url=rec.callback_url)

        if rec.kind == "interaction":
            if rec.interaction_type == "completion" and rec.mission_s256:
                m = self._b.missions.get(rec.mission_s256)
                if m and m.state == MissionState.ACTIVE:
                    self._b.missions[m.s256] = replace(m, state=MissionState.TERMINATED)
                    self._b.append_mission_log(
                        m.s256,
                        MissionLogEntry(
                            ts=utc_now(),
                            kind=MissionLogKind.AGENT_INTERACTION,
                            payload={"event": "mission_completed", "summary": rec.interaction_summary},
                        ),
                    )
            if rec.interaction_type == "question":
                ans = decision.answer_text or ""
                self._store.resolve_pending(
                    pending_id,
                    InteractionTerminalResult(body={"answer": ans}),
                )
                return DecisionResult(redirect_url=rec.callback_url)
            self._store.resolve_pending(
                pending_id,
                InteractionTerminalResult(body={"status": "ok"}),
            )
            return DecisionResult(redirect_url=rec.callback_url)

        if rec.kind == "token" and rec.token_request is not None:
            auth = self._federator.request_auth_token(
                rec.token_request.resource_token,
                self._agent_jwt_stub,
                rec.token_request.upstream_token,
            )
            if isinstance(auth, DeferredResponse):
                raise RuntimeError("federator unexpectedly deferred")
            self._store.resolve_pending(pending_id, auth)
            if rec.token_request.mission:
                mid = rec.token_request.mission.s256
                if mid in self._b.missions:
                    self._b.append_mission_log(
                        mid,
                        MissionLogEntry(
                            ts=utc_now(),
                            kind=MissionLogKind.TOKEN_REQUEST,
                            payload={"justification": rec.token_request.justification},
                        ),
                    )
            return DecisionResult(redirect_url=rec.callback_url)

        if rec.kind == "mission" and rec.mission_proposal is not None:
            m = mission_from_proposal(rec.mission_proposal, self._ps_issuer)
            self._record_mission(m)
            self._store.resolve_pending(pending_id, m)
            return DecisionResult(redirect_url=rec.callback_url)

        raise NotFoundError("invalid pending record")

    def mark_interacting(self, pending_id: str) -> None:
        self._store.update_pending(pending_id, status=PendingStatus.INTERACTING)
