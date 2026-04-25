"""In-memory UserConsent."""

from __future__ import annotations

from dataclasses import replace
from typing import Union

from ps.exceptions import NotFoundError
from ps.federation.as_federator import ASFederator
from ps.federation.agent_server_trust import normalize_issuer
from ps.impl.backend import utc_now
from ps.impl.mission_state import MissionStatePort
from ps.impl.memory_pending import MemoryPendingStore
from ps.impl.mission_utils import mission_from_proposal
from ps.models import (
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
from ps.service.auth_issuer import AuthTokenIssuer
from ps.service.user_consent import UserConsent


class MemoryUserConsent(UserConsent):
    def __init__(
        self,
        mission: MissionStatePort,
        store: Union[MemoryPendingStore, "DatabasePendingStore"],
        federator: ASFederator,
        auth_issuer: AuthTokenIssuer,
        *,
        agent_jwt_stub: str,
        ps_issuer: str,
    ) -> None:
        self._m = mission
        self._store = store
        self._federator = federator
        self._auth_issuer = auth_issuer
        self._agent_jwt_stub = agent_jwt_stub
        self._ps_issuer = ps_issuer.rstrip("/")

    def _record_mission(self, m: Mission) -> None:
        self._m.set_mission(m)
        self._m.append_mission_log(
            m.s256,
            MissionLogEntry(ts=utc_now(), kind=MissionLogKind.MISSION_APPROVED, payload={"agent_id": m.agent_id}),
        )

    def get_consent_context(self, code: str) -> ConsentContext:
        rec = self._store.lookup_code(code)
        justification = rec.token_request.justification if rec.token_request else None
        mission = None
        if rec.kind == "mission" and rec.mission_proposal:
            aid = rec.mission_proposal.agent_id
            for m in self._m.iter_missions():
                if m.agent_id == aid:
                    mission = m
                    break
        elif rec.kind == "interaction" and rec.mission_s256:
            mission = self._m.get_mission(rec.mission_s256)
        elif rec.kind == "token" and rec.token_request and rec.token_request.mission:
            mission = self._m.get_mission(rec.token_request.mission.s256)
        responses = tuple(rec.clarification_responses) if rec.clarification_responses else ()
        vclaims = rec.verified_resource_claims or {}
        resource_iss = str(vclaims["iss"]) if vclaims.get("iss") else None
        resource_scope = str(vclaims["scope"]) if vclaims.get("scope") else None
        rm = vclaims.get("mission")
        resource_mission_s256 = None
        if isinstance(rm, dict) and rm.get("s256"):
            resource_mission_s256 = str(rm["s256"])
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
                pending_kind=rec.kind,
                resource_iss=resource_iss,
                resource_scope=resource_scope,
                resource_mission_s256=resource_mission_s256,
            )
        return ConsentContext(
            pending_id=rec.pending_id,
            resource_name=None,
            scopes={},
            justification=justification,
            mission=mission,
            agent_name=None,
            clarification_responses=responses,
            pending_kind=rec.kind,
            resource_iss=resource_iss,
            resource_scope=resource_scope,
            resource_mission_s256=resource_mission_s256,
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
                m = self._m.get_mission(rec.mission_s256)
                if m and m.state == MissionState.ACTIVE:
                    self._m.set_mission(replace(m, state=MissionState.TERMINATED))
                    self._m.append_mission_log(
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
            tr = rec.token_request
            claims = rec.verified_resource_claims
            if tr.secure_mode and claims:
                aud = normalize_issuer(str(claims.get("aud", "")))
                psn = normalize_issuer(self._ps_issuer)
                cnf = rec.token_agent_cnf_jwk or tr.agent_cnf_jwk
                if aud == psn and cnf is not None:
                    auth = self._auth_issuer.issue(
                        agent_id=tr.agent_id,
                        agent_cnf_jwk=dict(cnf),
                        resource_claims=claims,
                        mission=tr.mission,
                    )
                else:
                    auth = self._federator.request_auth_token(
                        tr.resource_token,
                        self._agent_jwt_stub,
                        tr.upstream_token,
                    )
            else:
                auth = self._federator.request_auth_token(
                    tr.resource_token,
                    self._agent_jwt_stub,
                    tr.upstream_token,
                )
            if isinstance(auth, DeferredResponse):
                raise RuntimeError("federator unexpectedly deferred")
            self._store.resolve_pending(pending_id, auth)
            if rec.token_request.mission:
                mid = rec.token_request.mission.s256
                if self._m.has_mission(mid):
                    self._m.append_mission_log(
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
