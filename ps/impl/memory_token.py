"""In-memory TokenBroker: mode-3 resource token verification + PS-issued auth tokens."""

from __future__ import annotations

import logging
from typing import Union
from typing import Any

import aauth
from aauth import TokenError as AAuthTokenError

from aauth import errors as aauth_errors

from ps.exceptions import (
    ClarificationLimitError,
    MissionDeniedError,
    NotFoundError,
    ResourceTokenRejectError,
)
from ps.federation.as_federator import ASFederator
from ps.federation.agent_server_trust import (
    issuer_urls_equivalent,
    normalize_aud_claim,
    normalize_issuer,
)
from ps.impl.backend import utc_now
from ps.impl.mission_state import MissionStatePort
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
from ps.service.auth_issuer import AuthTokenIssuer
from ps.service.consent_scopes import ConsentScopeStore
from ps.service.mission_evaluator import MissionEvaluator, TokenRequestSummary
from ps.service.token_broker import TokenBroker
from ps.federation.resource_jwks import ResourceJWKSFetcher

logger = logging.getLogger(__name__)

_MAX_CLARIFICATION_ROUNDS = 5


from dataclasses import dataclass
from typing import Literal as _Literal


@dataclass(frozen=True, slots=True)
class _EvaluatorOutcome:
    kind: _Literal["allow", "clarify", "escalate"]
    payload: Any


class MemoryTokenBroker(TokenBroker):
    def __init__(
        self,
        store: Union[MemoryPendingStore, "DatabasePendingStore"],
        federator: ASFederator,
        mission: MissionStatePort,
        *,
        ps_origin: str,
        auth_issuer: AuthTokenIssuer,
        resource_jwks: ResourceJWKSFetcher,
        consent_scopes: ConsentScopeStore,
        agent_jwt_stub: str,
        auto_approve_without_consent: bool = False,
        insecure_dev: bool = False,
        evaluator: MissionEvaluator | None = None,
    ) -> None:
        self._store = store
        self._federator = federator
        self._m = mission
        self._ps_origin = normalize_issuer(ps_origin)
        self._auth_issuer = auth_issuer
        self._resource_jwks = resource_jwks
        self._consent_scopes = consent_scopes
        self._agent_jwt_stub = agent_jwt_stub
        self._auto = auto_approve_without_consent
        self._insecure_dev = insecure_dev
        self._evaluator = evaluator

    def _issue_or_fake_federate(
        self,
        request: TokenRequest,
        *,
        resource_claims: dict[str, Any] | None = None,
    ) -> TokenOutcome:
        """``aud`` is PS → real auth token; otherwise existing fake AS federator."""
        if resource_claims is None:
            return self._federator.request_auth_token(
                request.resource_token,
                self._agent_jwt_stub,
                request.upstream_token,
            )
        aud = normalize_aud_claim(resource_claims.get("aud"))
        if not issuer_urls_equivalent(aud, self._ps_origin):
            return self._federator.request_auth_token(
                request.resource_token,
                self._agent_jwt_stub,
                request.upstream_token,
            )
        if request.agent_cnf_jwk is None:
            raise NotFoundError("internal error: missing agent cnf.jwk for auth token issuance")
        return self._auth_issuer.issue(
            agent_id=request.agent_id,
            agent_cnf_jwk=request.agent_cnf_jwk,
            resource_claims=resource_claims,
            mission=request.mission,
            justification=request.justification,
            issue_method="autonomous",
        )

    def request_token(self, request: TokenRequest) -> TokenOutcome:
        if request.mission is not None:
            require_active_mission(self._m, request.mission)

        # Verify the resource token in secure mode; insecure_dev keeps claims empty.
        resource_claims: dict[str, Any] | None = None
        if request.secure_mode:
            try:
                resource_claims = aauth.verify_resource_token(
                    request.resource_token,
                    self._resource_jwks,
                    expected_aud=None,
                    expected_agent=request.agent_id,
                    expected_agent_jkt=request.agent_jkt,
                )
            except AAuthTokenError as e:
                logger.info("resource token verification failed: %s", e)
                msg = str(e).lower()
                code = aauth_errors.ERROR_INVALID_RESOURCE_TOKEN
                if "expired" in msg:
                    code = aauth_errors.ERROR_EXPIRED_RESOURCE_TOKEN
                raise ResourceTokenRejectError(str(e), error=code) from e

        # Layer 1 — mission-aware evaluation. Runs whenever the request carries a
        # mission and an evaluator is wired, in both insecure and secure modes. The
        # evaluator's verdict overrides scope-based and ``auto`` shortcircuits below.
        evaluator_escalation_reason: str | None = None
        if request.mission is not None and self._evaluator is not None:
            m = self._m.get_mission(request.mission.s256)
            if m is not None:
                outcome = self._apply_evaluator(request, m, resource_claims or {})
                if outcome.kind == "allow":
                    return outcome.payload  # type: ignore[return-value]
                if outcome.kind == "clarify":
                    return outcome.payload  # type: ignore[return-value]
                evaluator_escalation_reason = outcome.payload  # type: ignore[assignment]

        if not request.secure_mode:
            if self._auto and evaluator_escalation_reason is None:
                return self._federator.request_auth_token(
                    request.resource_token,
                    self._agent_jwt_stub,
                    request.upstream_token,
                )
            pid = self._store.create_pending(request)
            if evaluator_escalation_reason is not None:
                rec = self._store.get_record(pid)
                rec.evaluator_reason = evaluator_escalation_reason
            self._store.update_pending(pid, requirement=RequirementLevel.INTERACTION)
            val = self._store.get_pending(pid, for_poll=False)
            if isinstance(val, Mission):
                raise NotFoundError("unexpected mission outcome on token request")
            return val

        assert resource_claims is not None  # secure_mode is True here
        if evaluator_escalation_reason is None and (
            self._auto or not self._consent_scopes.requires_consent(resource_claims.get("scope"))
        ):
            return self._issue_or_fake_federate(request, resource_claims=resource_claims)

        pid = self._store.create_pending(request)
        rec = self._store.get_record(pid)
        rec.verified_resource_claims = resource_claims
        rec.token_agent_cnf_jwk = request.agent_cnf_jwk
        if evaluator_escalation_reason is not None:
            rec.evaluator_reason = evaluator_escalation_reason
        self._store.update_pending(pid, requirement=RequirementLevel.INTERACTION)
        val = self._store.get_pending(pid, for_poll=False)
        if isinstance(val, Mission):
            raise NotFoundError("unexpected mission outcome on token request")
        return val

    def _apply_evaluator(
        self,
        request: TokenRequest,
        mission: Mission,
        resource_claims: dict[str, Any],
    ) -> "_EvaluatorOutcome":
        """Run the evaluator, log the decision, and translate it into a control-flow shape.

        Returns:
          - ``("allow", AuthTokenResponse | DeferredResponse)`` — issued immediately, caller returns it.
          - ``("clarify", DeferredResponse)`` — clarification pending, caller returns it.
          - ``("escalate", reason)`` — caller falls through to consent with the reason attached.

        Raises ``MissionDeniedError`` for the deny decision.
        """
        log = self._m.get_mission_log(mission.s256)
        iss = resource_claims.get("iss")
        scope = resource_claims.get("scope")
        summary = TokenRequestSummary(
            agent_id=request.agent_id,
            resource_iss=str(iss) if iss else None,
            resource_scope=str(scope) if scope else None,
            justification=request.justification,
            upstream_token_present=request.upstream_token is not None,
        )
        decision = self._evaluator.evaluate(mission, log, summary)  # type: ignore[union-attr]

        self._m.append_mission_log(
            mission.s256,
            MissionLogEntry(
                ts=utc_now(),
                kind=MissionLogKind.TOKEN_REQUEST,
                payload={
                    "stage": "evaluator",
                    "decision": decision.decision,
                    "reason": decision.reason,
                    "resource_iss": summary.resource_iss,
                    "resource_scope": summary.resource_scope,
                    "justification": request.justification,
                },
            ),
        )

        if decision.decision == "deny":
            raise MissionDeniedError(decision.reason)

        if decision.decision == "allow":
            issued = self._issue_or_fake_federate(request, resource_claims=resource_claims)
            return _EvaluatorOutcome(kind="allow", payload=issued)

        if decision.decision == "clarify":
            pid = self._store.create_pending(request)
            rec = self._store.get_record(pid)
            rec.verified_resource_claims = resource_claims
            rec.token_agent_cnf_jwk = request.agent_cnf_jwk
            rec.evaluator_reason = decision.reason
            self._store.update_pending(
                pid,
                requirement=RequirementLevel.CLARIFICATION,
                clarification=decision.clarification_question,
                status=PendingStatus.PENDING,
            )
            out = self._store.get_pending(pid, for_poll=False)
            if not isinstance(out, DeferredResponse):
                raise NotFoundError("unexpected non-deferred outcome on clarify path")
            return _EvaluatorOutcome(kind="clarify", payload=out)

        return _EvaluatorOutcome(kind="escalate", payload=decision.reason)

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
            self._m.append_mission_log(
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
        rec = self._store.get_record(pending_id)
        tr = rec.token_request
        if tr is not None and tr.secure_mode:
            try:
                claims = aauth.verify_resource_token(
                    new_resource_token,
                    self._resource_jwks,
                    expected_aud=None,
                    expected_agent=tr.agent_id,
                    expected_agent_jkt=tr.agent_jkt,
                )
            except AAuthTokenError as e:
                msg = str(e).lower()
                code = aauth_errors.ERROR_INVALID_RESOURCE_TOKEN
                if "expired" in msg:
                    code = aauth_errors.ERROR_EXPIRED_RESOURCE_TOKEN
                raise ResourceTokenRejectError(str(e), error=code) from e
            rec.verified_resource_claims = claims
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
