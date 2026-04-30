"""Unified Person Portal: Person Server + Agent Server on one FastAPI app."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, Literal

from aauth import errors as aauth_errors
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, model_validator

from agent_server.api.metadata import well_known_agent_payload
from agent_server.http.bodies import RegisterBody
from agent_server.api.person_routes import (
    handle_approve,
    handle_create_binding_from_stable_pub,
    handle_deny,
    handle_link,
    handle_list_bindings,
    handle_list_registrations,
    handle_revoke_binding,
)
from agent_server.api.refresh_routes import handle_refresh
from agent_server.api.registration_routes import handle_poll_pending, handle_register
from agent_server.exceptions import (
    BindingNotFoundError as ASBindingNotFoundError,
    BindingRevokedError,
    DuplicateStableKeyError,
    InvalidSignatureError,
    PendingDeniedError as ASPendingDeniedError,
    PendingExpiredError as ASPendingExpiredError,
    PendingNotFoundError,
    StableKeyAlreadyBoundError,
)
from agent_server.http.config import AgentServerSettings
from agent_server.http.errors import aauth_json_error as as_aauth_json_error
from agent_server.impl import ASContainer, build_memory_as
from persistence.wiring import (
    build_engine_and_session_from_url,
    build_persisted_as,
    build_persisted_ps,
    init_db,
)
from agent_server.models import VerifiedRequest
from ps.api.admin_routes import get_mission_route, list_missions_route, patch_mission
from ps.api.trust_routes import TrustedAgentIn, handle_add_trusted, handle_list_trusted, handle_remove_trusted
from ps.api.agent_routes import (
    ClarificationPostBody,
    UpdatedTokenPostBody,
    cancel_pending_route,
    create_mission_route,
    get_pending_route,
    post_pending_route,
    request_token_route,
)
from ps.api.user_mission_routes import (
    get_user_mission_route,
    list_user_missions_route,
    patch_user_mission_route,
    user_consent_queue,
)
from ps.api.user_routes import get_interaction_route, post_decision_route
from ps.exceptions import (
    AgentTokenRejectError,
    ClarificationLimitError,
    ForbiddenOwnerError,
    InvalidInteractionCodeError,
    MissionTerminatedError,
    NotFoundError,
    PendingDeniedError as PSPendingDeniedError,
    PendingExpiredError,
    PendingGoneError,
    ResourceTokenRejectError,
    SlowDownError,
)
from ps.http.config import PSHttpSettings
from ps.federation.agent_jwks import DeferredAgentSelfJWKS
from ps.http.deps import (
    TokenAgentContext,
    get_settings as get_ps_settings_dep,
    parse_prefer_wait,
    require_agent_id,
    require_token_agent,
)
from ps.http.encoding import (
    auth_token_http_dict,
    build_aauth_requirement_header,
    consent_context_http_dict,
    deferred_body_dict,
    mission_detail_dict,
    mission_list_dict,
    mission_state_from_query,
)
from ps.http.errors import aauth_json_error as ps_aauth_json_error
from ps.http.mission_header import build_aauth_mission_response_header, parse_aauth_mission_header
from ps.impl import PSContainer, build_memory_ps
from ps.models import (
    AgentInteractionRequest,
    AuditRequest,
    AuthTokenResponse,
    DeferredResponse,
    InteractionTerminalResult,
    Mission,
    MissionProposal,
    MissionRef,
    MissionState,
    PermissionRequest,
    TokenRequest,
    ToolSpec,
    UserDecision,
)
from ps.utils.sanitize import sanitize_markdown_input

from portal.http.deps import (
    get_as_settings,
    get_container,
    require_http_sig,
    require_portal_admin,
    require_portal_person_api,
    require_portal_user_id,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PS body models (same as ps/http/app.py)
# ---------------------------------------------------------------------------


class ToolBody(BaseModel):
    name: str
    description: str


class MissionRefBody(BaseModel):
    approver: str
    s256: str


class MissionProposalBody(BaseModel):
    description: str = Field(..., description="Markdown mission description (SPEC)")
    tools: list[ToolBody] | None = None
    owner_hint: str | None = Field(
        default=None,
        description="Legal owner id for mission control / consent scoping.",
    )


class TokenRequestBody(BaseModel):
    resource_token: str
    upstream_token: str | None = None
    justification: str | None = None
    login_hint: str | None = None
    tenant: str | None = None
    domain_hint: str | None = None
    mission: MissionRefBody | None = None


class PendingPostBody(BaseModel):
    clarification_response: str | None = None
    resource_token: str | None = None
    justification: str | None = None

    @model_validator(mode="after")
    def exactly_one_action(self) -> PendingPostBody:
        has_c = self.clarification_response is not None
        has_t = self.resource_token is not None
        if has_c == has_t:
            raise ValueError("Provide either clarification_response or resource_token, not both")
        return self


class UserDecisionBody(BaseModel):
    approved: bool
    clarification_question: str | None = None
    answer_text: str | None = None


class MissionPatchBody(BaseModel):
    state: Literal[MissionState.TERMINATED]


class PermissionBody(BaseModel):
    action: str
    description: str | None = None
    parameters: dict[str, Any] | None = None
    mission: MissionRefBody | None = None


class AuditBody(BaseModel):
    mission: MissionRefBody
    action: str
    description: str | None = None
    parameters: dict[str, Any] | None = None
    result: dict[str, Any] | None = None


class AgentInteractionBody(BaseModel):
    type: Literal["interaction", "payment", "question", "completion"]
    description: str | None = None
    url: str | None = None
    code: str | None = None
    question: str | None = None
    summary: str | None = None
    mission: MissionRefBody | None = None


# ---------------------------------------------------------------------------
# AS body models
# ---------------------------------------------------------------------------


class LinkBody(BaseModel):
    agent_id: str = Field(..., description="Existing binding agent_id to link this device into")


def _is_agent_protocol_path(path: str) -> bool:
    return (
        path.startswith("/mission")
        or path.startswith("/token")
        or path.startswith("/pending")
        or path.startswith("/permission")
        or path.startswith("/audit")
        or path == "/interaction"
    )


def _portal_agent_protocol_path(path: str) -> bool:
    """PS agent routes + AS /register + /refresh (for validation + 401 shaping)."""
    if path.startswith("/register") or path.startswith("/refresh"):
        return True
    return _is_agent_protocol_path(path)


def _json_deferred(d: DeferredResponse) -> JSONResponse:
    headers: dict[str, str] = {
        "Location": d.pending_url,
        "Retry-After": str(d.retry_after),
        "Cache-Control": "no-store",
    }
    req = build_aauth_requirement_header(d)
    if req:
        headers["AAuth-Requirement"] = req
    return JSONResponse(status_code=202, content=deferred_body_dict(d), headers=headers)


def _token_outcome_response(
    out: AuthTokenResponse | DeferredResponse | Mission | InteractionTerminalResult,
) -> JSONResponse:
    if isinstance(out, AuthTokenResponse):
        return JSONResponse(auth_token_http_dict(out))
    if isinstance(out, Mission):
        raise RuntimeError("unexpected mission on token flow")
    if isinstance(out, InteractionTerminalResult):
        return JSONResponse(out.body)
    return _json_deferred(out)


def _mission_approval_response(m: Mission) -> Response:
    hdr = build_aauth_mission_response_header(m.approver, m.s256)
    return Response(
        content=m.blob_bytes,
        media_type="application/json",
        headers={
            "AAuth-Mission": hdr,
            "Cache-Control": "no-store",
        },
    )


def _mission_outcome_response(out: Mission | DeferredResponse) -> Response | JSONResponse:
    if isinstance(out, Mission):
        return _mission_approval_response(out)
    return _json_deferred(out)


def create_portal_app(
    ps_settings: PSHttpSettings | None = None,
    as_settings: AgentServerSettings | None = None,
) -> FastAPI:
    ps_settings = ps_settings or PSHttpSettings()
    base_as = as_settings or AgentServerSettings()
    as_settings = base_as.model_copy(
        update={
            "issuer": ps_settings.public_origin.rstrip("/"),
            "public_origin": ps_settings.public_origin.rstrip("/"),
            "client_name": "AAuth Person Portal",
        }
    )

    defer_as_jwks = DeferredAgentSelfJWKS()
    database_url = (
        ps_settings.database_url
        or as_settings.database_url
        or os.environ.get("AAUTH_DATABASE_URL")
    )
    db_engine: Any = None
    if database_url:
        db_engine, session_factory = build_engine_and_session_from_url(database_url)
        init_db(db_engine)
        ps: PSContainer = build_persisted_ps(
            session_factory,
            public_origin=ps_settings.public_origin,
            auto_approve_token=ps_settings.auto_approve_token,
            auto_approve_mission=ps_settings.auto_approve_mission,
            agent_jwt_stub=ps_settings.agent_jwt_stub,
            pending_ttl_seconds=ps_settings.pending_ttl_seconds,
            signing_key_path=ps_settings.signing_key_path,
            trust_file=ps_settings.trust_file,
            auth_token_lifetime=ps_settings.auth_token_lifetime,
            user_id=ps_settings.user_id,
            insecure_dev=ps_settings.insecure_dev,
            self_jwks_provider=defer_as_jwks,
        )
        container: ASContainer = build_persisted_as(
            session_factory,
            issuer=as_settings.issuer,
            server_domain=as_settings.server_domain,
            signing_key_path=as_settings.signing_key_path,
            previous_key_path=as_settings.previous_key_path,
            agent_token_lifetime=as_settings.agent_token_lifetime,
            registration_ttl=as_settings.registration_ttl,
            signature_window=as_settings.signature_window,
        )
    else:
        ps = build_memory_ps(
            public_origin=ps_settings.public_origin,
            auto_approve_token=ps_settings.auto_approve_token,
            auto_approve_mission=ps_settings.auto_approve_mission,
            agent_jwt_stub=ps_settings.agent_jwt_stub,
            pending_ttl_seconds=ps_settings.pending_ttl_seconds,
            signing_key_path=ps_settings.signing_key_path,
            trust_file=ps_settings.trust_file,
            auth_token_lifetime=ps_settings.auth_token_lifetime,
            user_id=ps_settings.user_id,
            insecure_dev=ps_settings.insecure_dev,
            self_jwks_provider=defer_as_jwks,
        )
        container = build_memory_as(
            issuer=as_settings.issuer,
            server_domain=as_settings.server_domain,
            signing_key_path=as_settings.signing_key_path,
            previous_key_path=as_settings.previous_key_path,
            agent_token_lifetime=as_settings.agent_token_lifetime,
            registration_ttl=as_settings.registration_ttl,
            signature_window=as_settings.signature_window,
        )
    defer_as_jwks.set(container.signing.get_jwks)

    @asynccontextmanager
    async def _portal_lifespan(_app: FastAPI) -> Any:
        yield
        if db_engine is not None:
            db_engine.dispose()

    app = FastAPI(
        title="AAuth Person Portal",
        version="0.1.0",
        description="Unified Person Server + Agent Server (single origin).",
        lifespan=_portal_lifespan,
    )
    app.state.settings = ps_settings
    app.state.ps_settings = ps_settings
    app.state.as_settings = as_settings
    app.state.ps = ps
    app.state.container = container
    app.state.db_engine = db_engine

    meta_ps = ps_settings.metadata()
    meta_as = as_settings.metadata()

    # --- PS exception handlers ---
    @app.exception_handler(MissionTerminatedError)
    async def mission_terminated_handler(
        _request: Request, _exc: MissionTerminatedError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=403,
            content={"error": "mission_terminated", "mission_status": "terminated"},
        )

    @app.exception_handler(InvalidInteractionCodeError)
    async def invalid_interaction_code_handler(
        _request: Request, _exc: InvalidInteractionCodeError
    ) -> JSONResponse:
        return ps_aauth_json_error(
            410,
            aauth_errors.ERROR_INVALID_CODE,
            "interaction code not recognized or already consumed",
        )

    @app.exception_handler(NotFoundError)
    async def not_found_handler(_request: Request, exc: NotFoundError) -> JSONResponse:
        msg = str(exc) or "not found"
        return ps_aauth_json_error(404, aauth_errors.ERROR_INVALID_REQUEST, msg)

    @app.exception_handler(PendingGoneError)
    async def gone_handler(_request: Request, _exc: PendingGoneError) -> JSONResponse:
        return ps_aauth_json_error(410, aauth_errors.ERROR_INVALID_CODE, "pending request was cancelled")

    @app.exception_handler(PSPendingDeniedError)
    async def ps_denied_handler(_request: Request, exc: PSPendingDeniedError) -> JSONResponse:
        reason = exc.reason
        if reason == "abandoned":
            return ps_aauth_json_error(403, aauth_errors.ERROR_ABANDONED, "user did not complete interaction")
        if reason == "denied":
            return ps_aauth_json_error(403, aauth_errors.ERROR_DENIED, "request was denied")
        return ps_aauth_json_error(403, aauth_errors.ERROR_DENIED, reason)

    @app.exception_handler(PendingExpiredError)
    async def expired_handler(_request: Request, _exc: PendingExpiredError) -> JSONResponse:
        return ps_aauth_json_error(408, aauth_errors.ERROR_EXPIRED, "pending request expired")

    @app.exception_handler(SlowDownError)
    async def slow_handler(_request: Request, _exc: SlowDownError) -> JSONResponse:
        return ps_aauth_json_error(429, aauth_errors.ERROR_SLOW_DOWN, "polling too frequently")

    @app.exception_handler(ClarificationLimitError)
    async def clar_limit_handler(_request: Request, _exc: ClarificationLimitError) -> JSONResponse:
        return ps_aauth_json_error(
            400,
            aauth_errors.ERROR_INVALID_REQUEST,
            "clarification round limit exceeded",
        )

    @app.exception_handler(ResourceTokenRejectError)
    async def resource_token_reject_handler(
        _request: Request, exc: ResourceTokenRejectError
    ) -> JSONResponse:
        return ps_aauth_json_error(401, exc.error, exc.message)

    @app.exception_handler(AgentTokenRejectError)
    async def agent_token_reject_handler(
        _request: Request, exc: AgentTokenRejectError
    ) -> JSONResponse:
        return ps_aauth_json_error(401, exc.error, exc.message)

    @app.exception_handler(ForbiddenOwnerError)
    async def forbidden_owner_handler(_request: Request, _exc: ForbiddenOwnerError) -> JSONResponse:
        return ps_aauth_json_error(403, aauth_errors.ERROR_DENIED, "not owner of this mission")

    # --- AS exception handlers ---
    @app.exception_handler(InvalidSignatureError)
    async def invalid_sig_handler(_req: Request, exc: InvalidSignatureError) -> JSONResponse:
        return as_aauth_json_error(401, aauth_errors.ERROR_INVALID_SIGNATURE, str(exc))

    @app.exception_handler(PendingNotFoundError)
    async def pending_not_found_handler(_req: Request, exc: PendingNotFoundError) -> JSONResponse:
        return as_aauth_json_error(404, aauth_errors.ERROR_INVALID_REQUEST, str(exc))

    @app.exception_handler(ASPendingDeniedError)
    async def as_pending_denied_handler(_req: Request, _exc: ASPendingDeniedError) -> JSONResponse:
        return JSONResponse(status_code=403, content={"error": "denied"})

    @app.exception_handler(ASPendingExpiredError)
    async def as_pending_expired_handler(_req: Request, _exc: ASPendingExpiredError) -> JSONResponse:
        return JSONResponse(status_code=410, content={"error": "expired"})

    @app.exception_handler(ASBindingNotFoundError)
    async def binding_not_found_handler(_req: Request, exc: ASBindingNotFoundError) -> JSONResponse:
        return as_aauth_json_error(404, aauth_errors.ERROR_INVALID_REQUEST, str(exc))

    @app.exception_handler(BindingRevokedError)
    async def binding_revoked_handler(_req: Request, exc: BindingRevokedError) -> JSONResponse:
        return as_aauth_json_error(401, aauth_errors.ERROR_INVALID_REQUEST, str(exc))

    @app.exception_handler(DuplicateStableKeyError)
    async def dup_key_handler(_req: Request, exc: DuplicateStableKeyError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"error": "conflict", "detail": str(exc)})

    @app.exception_handler(StableKeyAlreadyBoundError)
    async def stable_key_bound_handler(
        _req: Request, exc: StableKeyAlreadyBoundError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=409,
            content={
                "error": "conflict",
                "detail": str(exc),
                "agent_id": exc.agent_id,
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        if _portal_agent_protocol_path(request.url.path):
            return as_aauth_json_error(400, aauth_errors.ERROR_INVALID_REQUEST, str(exc))
        return JSONResponse(status_code=422, content={"detail": exc.errors()})

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        path = request.url.path
        if exc.status_code == 401:
            if _portal_agent_protocol_path(path):
                desc = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
                return as_aauth_json_error(401, aauth_errors.ERROR_INVALID_SIGNATURE, desc)
            return JSONResponse(status_code=401, content={"detail": exc.detail})
        if exc.status_code == 403 and path.startswith("/user"):
            return JSONResponse(status_code=403, content={"detail": exc.detail})
        if exc.status_code == 403:
            return JSONResponse(status_code=403, content={"detail": exc.detail})
        if exc.status_code == 503:
            return JSONResponse(status_code=503, content={"detail": exc.detail})
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    def _well_known_person_payload() -> dict[str, Any]:
        return {
            "issuer": meta_ps.issuer,
            "token_endpoint": meta_ps.token_endpoint,
            "mission_endpoint": meta_ps.mission_endpoint,
            "permission_endpoint": meta_ps.permission_endpoint,
            "audit_endpoint": meta_ps.audit_endpoint,
            "interaction_endpoint": meta_ps.interaction_endpoint,
            "mission_control_endpoint": meta_ps.mission_control_endpoint,
            "jwks_uri": meta_ps.jwks_uri,
        }

    @app.get("/.well-known/aauth-person.json")
    def well_known_person():
        return _well_known_person_payload()

    @app.get("/.well-known/aauth-agent.json")
    def well_known_agent() -> dict[str, Any]:
        return well_known_agent_payload(
            issuer=meta_as.issuer,
            jwks_uri=meta_as.jwks_uri,
            client_name=meta_as.client_name,
            registration_endpoint=meta_as.registration_endpoint,
            refresh_endpoint=meta_as.refresh_endpoint,
        )

    @app.get("/.well-known/jwks.json")
    def jwks() -> dict[str, Any]:
        ps_keys = ps.ps_signing.get_jwks().get("keys", [])
        as_keys = container.signing.get_jwks().get("keys", [])
        return {"keys": [*ps_keys, *as_keys]}

    # --- PS routes ---
    @app.post("/mission")
    async def post_mission(
        body: MissionProposalBody,
        request: Request,
        agent_id: Annotated[str, Depends(require_agent_id)],
    ):
        prefer = parse_prefer_wait(request.headers.get("prefer"))
        if prefer is not None:
            logger.debug("POST /mission Prefer: wait=%s (long-poll not implemented)", prefer)
        tools: tuple[ToolSpec, ...] = ()
        if body.tools:
            tools = tuple(ToolSpec(name=t.name, description=t.description) for t in body.tools)
        proposal = MissionProposal(
            agent_id=agent_id,
            description=sanitize_markdown_input(body.description),
            tools=tools,
            owner_hint=body.owner_hint,
        )
        out = create_mission_route(ps.lifecycle, proposal)
        return _mission_outcome_response(out)

    @app.post("/token")
    async def post_token(
        body: TokenRequestBody,
        request: Request,
        tok_agent: Annotated[TokenAgentContext, Depends(require_token_agent)],
    ):
        prefer = parse_prefer_wait(request.headers.get("prefer"))
        if prefer is not None:
            logger.debug("POST /token Prefer: wait=%s (long-poll not implemented)", prefer)
        just = sanitize_markdown_input(body.justification) if body.justification else None
        mref: MissionRef | None = None
        if body.mission is not None:
            mref = MissionRef(approver=body.mission.approver, s256=body.mission.s256)
        hdr_m = parse_aauth_mission_header(request.headers.get("aauth-mission"))
        if mref is None and hdr_m is not None:
            mref = hdr_m
        req = TokenRequest(
            agent_id=tok_agent.agent_id,
            resource_token=body.resource_token,
            justification=just,
            upstream_token=body.upstream_token,
            login_hint=body.login_hint,
            tenant=body.tenant,
            domain_hint=body.domain_hint,
            mission=mref,
            agent_cnf_jwk=tok_agent.agent_cnf_jwk,
            agent_jkt=tok_agent.agent_jkt,
            secure_mode=tok_agent.secure_mode,
        )
        out = request_token_route(ps.token_broker, req)
        return _token_outcome_response(out)

    @app.post("/permission")
    async def post_permission(
        body: PermissionBody,
        agent_id: Annotated[str, Depends(require_agent_id)],
    ):
        mref = MissionRef(approver=body.mission.approver, s256=body.mission.s256) if body.mission else None
        req = PermissionRequest(
            action=body.action,
            description=sanitize_markdown_input(body.description) if body.description else None,
            parameters=body.parameters,
            mission=mref,
            agent_id=agent_id,
        )
        try:
            out = ps.governance.post_permission(req)
        except NotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        return {"permission": out.permission, **({"reason": out.reason} if out.reason else {})}

    @app.post("/audit", status_code=201)
    async def post_audit(
        body: AuditBody,
        agent_id: Annotated[str, Depends(require_agent_id)],
    ):
        req = AuditRequest(
            mission=MissionRef(approver=body.mission.approver, s256=body.mission.s256),
            action=body.action,
            description=sanitize_markdown_input(body.description) if body.description else None,
            parameters=body.parameters,
            result=body.result,
            agent_id=agent_id,
        )
        try:
            ps.governance.post_audit(req)
        except NotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        return Response(status_code=201)

    @app.post("/interaction")
    async def post_agent_interaction(
        body: AgentInteractionBody,
        agent_id: Annotated[str, Depends(require_agent_id)],
    ):
        mref = (
            MissionRef(approver=body.mission.approver, s256=body.mission.s256) if body.mission else None
        )
        req = AgentInteractionRequest(
            type=body.type,
            description=sanitize_markdown_input(body.description) if body.description else None,
            url=body.url,
            code=body.code,
            question=sanitize_markdown_input(body.question) if body.question else None,
            summary=sanitize_markdown_input(body.summary) if body.summary else None,
            mission=mref,
            agent_id=agent_id,
        )
        try:
            d = ps.governance.post_agent_interaction(req)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        except NotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        return _json_deferred(d)

    @app.get("/pending/{pending_id}")
    async def get_pending_ps(
        pending_id: str,
        request: Request,
        agent_id: Annotated[str, Depends(require_agent_id)],
    ):
        prefer = parse_prefer_wait(request.headers.get("prefer"))
        if prefer is not None:
            logger.debug("GET /pending Prefer: wait=%s (long-poll not implemented)", prefer)
        out = get_pending_route(ps.token_broker, pending_id, agent_id)
        return _token_outcome_response(out)

    @app.post("/pending/{pending_id}")
    async def post_pending_ps(
        pending_id: str,
        body: PendingPostBody,
        agent_id: Annotated[str, Depends(require_agent_id)],
    ):
        if body.clarification_response is not None:
            clar = sanitize_markdown_input(body.clarification_response)
            b: ClarificationPostBody | UpdatedTokenPostBody = ClarificationPostBody(clarification_response=clar)
        else:
            just = sanitize_markdown_input(body.justification) if body.justification else None
            b = UpdatedTokenPostBody(resource_token=body.resource_token or "", justification=just)
        try:
            out = post_pending_route(ps.token_broker, pending_id, agent_id, b)
        except ClarificationLimitError:
            raise ClarificationLimitError() from None
        return _token_outcome_response(out)

    @app.delete("/pending/{pending_id}", status_code=204)
    async def delete_pending_ps(pending_id: str, agent_id: Annotated[str, Depends(require_agent_id)]):
        cancel_pending_route(ps.token_broker, pending_id, agent_id)

    @app.get("/consent")
    def get_consent(
        code: str,
        settings: Annotated[PSHttpSettings, Depends(get_ps_settings_dep)],
        callback: str | None = None,
    ):
        if settings.require_user_session:
            pass
        ctx = get_interaction_route(ps.user_consent, code)
        ps.pending_store.set_callback_url(ctx.pending_id, callback)
        ps.user_consent.mark_interacting(ctx.pending_id)
        return consent_context_http_dict(ctx)

    def _consent_decision_impl(pending_id: str, body: UserDecisionBody) -> JSONResponse:
        decision = UserDecision(
            approved=body.approved,
            clarification_question=body.clarification_question,
            answer_text=body.answer_text,
        )
        try:
            result = post_decision_route(ps.user_consent, pending_id, decision)
        except NotFoundError as e:
            raise NotFoundError(str(e)) from e
        payload: dict[str, Any] = {}
        if result.redirect_url:
            payload["redirect_url"] = result.redirect_url
        return JSONResponse(status_code=200, content=payload)

    @app.post("/consent/{pending_id}/decision")
    def post_consent_decision(pending_id: str, body: UserDecisionBody):
        return _consent_decision_impl(pending_id, body)

    @app.get("/interaction", include_in_schema=False)
    def get_interaction_legacy(
        code: str,
        settings: Annotated[PSHttpSettings, Depends(get_ps_settings_dep)],
        callback: str | None = None,
    ):
        if settings.require_user_session:
            pass
        ctx = get_interaction_route(ps.user_consent, code)
        ps.pending_store.set_callback_url(ctx.pending_id, callback)
        ps.user_consent.mark_interacting(ctx.pending_id)
        return consent_context_http_dict(ctx)

    @app.post("/interaction/{pending_id}/decision", include_in_schema=False)
    def post_interaction_legacy(pending_id: str, body: UserDecisionBody):
        return _consent_decision_impl(pending_id, body)

    @app.get("/missions")
    def list_missions(
        _admin: Annotated[None, Depends(require_portal_admin)],
        agent_id: str | None = None,
        state: str | None = None,
    ) -> list[dict[str, Any]]:
        st = mission_state_from_query(state)
        missions = list_missions_route(ps.mission_control, agent_id, st)
        return [mission_list_dict(m) for m in missions]

    @app.get("/missions/{s256}")
    def inspect_mission(s256: str, _admin: Annotated[None, Depends(require_portal_admin)]):
        try:
            m = get_mission_route(ps.mission_control, s256)
            log = ps.mission_control.mission_log(s256)
        except NotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        detail = mission_detail_dict(m)
        detail["log"] = [
            {"ts": e.ts.isoformat(), "kind": e.kind.value, "payload": e.payload} for e in log
        ]
        return detail

    @app.patch("/missions/{s256}")
    def patch_mission_route(
        s256: str, body: MissionPatchBody, _admin: Annotated[None, Depends(require_portal_admin)]
    ):
        try:
            m = patch_mission(ps.mission_control, s256, body.state)
        except NotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return mission_detail_dict(m)

    @app.get("/user/missions")
    def list_user_missions(
        user_id: Annotated[str, Depends(require_portal_user_id)],
    ) -> list[dict[str, Any]]:
        missions = list_user_missions_route(ps.mission_control, user_id)
        return [mission_list_dict(m) for m in missions]

    @app.get("/user/missions/{s256}")
    def inspect_user_mission(s256: str, user_id: Annotated[str, Depends(require_portal_user_id)]):
        try:
            m = get_user_mission_route(ps.mission_control, s256, user_id)
            log = ps.mission_control.mission_log(s256)
        except NotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        except ForbiddenOwnerError:
            raise
        detail = mission_detail_dict(m)
        detail["log"] = [
            {"ts": e.ts.isoformat(), "kind": e.kind.value, "payload": e.payload} for e in log
        ]
        return detail

    @app.patch("/user/missions/{s256}")
    def patch_user_mission_http(
        s256: str, body: MissionPatchBody, user_id: Annotated[str, Depends(require_portal_user_id)]
    ):
        try:
            m = patch_user_mission_route(ps.mission_control, s256, user_id, body.state)
        except NotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        except ForbiddenOwnerError:
            raise
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return mission_detail_dict(m)

    @app.get("/user/consent")
    def list_user_consent(user_id: Annotated[str, Depends(require_portal_user_id)]) -> list[dict[str, Any]]:
        return user_consent_queue(ps.pending_store, user_id)

    @app.get("/admin/pending")
    def admin_list_pending(_admin: Annotated[None, Depends(require_portal_admin)]) -> list[dict[str, Any]]:
        return ps.pending_store.list_open_pending_for_admin()

    @app.get("/admin/issued-tokens")
    def admin_list_issued_tokens(_admin: Annotated[None, Depends(require_portal_admin)]) -> list[dict[str, Any]]:
        return ps.issued_token_store.list_issued()

    @app.get("/admin/consent-scopes")
    def get_consent_scopes_portal(_admin: Annotated[None, Depends(require_portal_admin)]) -> dict[str, Any]:
        return {"scopes": ps.consent_scopes.get_scopes()}

    @app.post("/admin/consent-scopes", status_code=201)
    def add_consent_scope_portal(
        body: dict[str, str],
        _admin: Annotated[None, Depends(require_portal_admin)],
    ) -> dict[str, Any]:
        scope = body.get("scope", "").strip()
        if not scope:
            raise HTTPException(status_code=400, detail="scope field required and must be non-empty")
        try:
            added = ps.consent_scopes.add_scope(scope)
            if not added:
                raise HTTPException(status_code=409, detail=f"Scope '{scope}' already exists")
            return {"scope": scope, "added": True}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.delete("/admin/consent-scopes/{scope}", status_code=204)
    def remove_consent_scope_portal(
        scope: str,
        _admin: Annotated[None, Depends(require_portal_admin)],
    ) -> Response:
        removed = ps.consent_scopes.remove_scope(scope)
        if not removed:
            raise HTTPException(status_code=404, detail=f"Scope '{scope}' not found")
        return Response(status_code=204)

    @app.get("/person/trusted-agent-servers")
    def list_trusted_agent_servers_portal(
        _admin: Annotated[None, Depends(require_portal_admin)],
    ) -> list[dict[str, Any]]:
        return handle_list_trusted(ps.trust_registry, ps_origin=ps_settings.public_origin.rstrip("/"))

    @app.post("/person/trusted-agent-servers", status_code=201)
    def add_trusted_agent_server_portal(
        body: TrustedAgentIn,
        _admin: Annotated[None, Depends(require_portal_admin)],
    ) -> dict[str, Any]:
        try:
            entry = handle_add_trusted(ps.trust_registry, body)
        except (OSError, ValueError) as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return {
            "issuer": entry.issuer,
            "display_name": entry.display_name,
            "jwks_uri": entry.jwks_uri,
            "jwks_fingerprint": entry.jwks_fingerprint,
            "added_at": entry.added_at,
        }

    @app.delete("/person/trusted-agent-servers", status_code=204)
    def remove_trusted_agent_server_portal(
        issuer: str,
        _admin: Annotated[None, Depends(require_portal_admin)],
    ) -> Response:
        if not handle_remove_trusted(ps.trust_registry, issuer):
            raise HTTPException(status_code=404, detail="issuer not in trust registry")
        return Response(status_code=204)

    # --- AS agent-facing ---
    @app.post("/register", status_code=202)
    async def post_register(
        body: RegisterBody,
        verified: Annotated[VerifiedRequest, Depends(require_http_sig)],
        container: Annotated[ASContainer, Depends(get_container)],
        settings: Annotated[AgentServerSettings, Depends(get_as_settings)],
    ):
        result = handle_register(
            verified=verified,
            stable_pub=body.stable_pub,
            agent_name=body.agent_name,
            registrations=container.registrations,
            bindings=container.bindings,
            token_factory=container.token_factory,
            server_domain=settings.server_domain,
        )
        if result["immediate"]:
            return JSONResponse(status_code=200, content={"agent_token": result["agent_token"]})

        pending_id = result["pending_id"]
        expires_at = result["expires_at"]
        return JSONResponse(
            status_code=202,
            content={"status": "pending", "expires_at": expires_at.isoformat()},
            headers={
                "Location": f"/register/pending/{pending_id}",
                "Retry-After": "5",
                "Cache-Control": "no-store",
            },
        )

    @app.get("/register/pending/{pending_id}")
    async def get_register_pending(
        pending_id: str,
        verified: Annotated[VerifiedRequest, Depends(require_http_sig)],
        container: Annotated[ASContainer, Depends(get_container)],
    ):
        result = handle_poll_pending(
            pending_id=pending_id,
            verified=verified,
            registrations=container.registrations,
            bindings=container.bindings,
            token_factory=container.token_factory,
        )
        if "agent_token" in result:
            return JSONResponse(status_code=200, content=result)
        return JSONResponse(
            status_code=202,
            content=result,
            headers={"Retry-After": "5", "Cache-Control": "no-store"},
        )

    @app.post("/refresh")
    async def post_refresh(
        verified: Annotated[VerifiedRequest, Depends(require_http_sig)],
        container: Annotated[ASContainer, Depends(get_container)],
    ):
        result = handle_refresh(
            verified=verified,
            bindings=container.bindings,
            token_factory=container.token_factory,
        )
        return JSONResponse(status_code=200, content=result)

    # --- AS person-facing ---
    @app.get("/person/registrations")
    def list_registrations(
        _person: Annotated[None, Depends(require_portal_person_api)],
        container: Annotated[ASContainer, Depends(get_container)],
    ) -> list[dict[str, Any]]:
        return handle_list_registrations(container.registrations)

    @app.post("/person/registrations/{pending_id}/approve")
    def approve_registration(
        pending_id: str,
        _person: Annotated[None, Depends(require_portal_person_api)],
        container: Annotated[ASContainer, Depends(get_container)],
        settings: Annotated[AgentServerSettings, Depends(get_as_settings)],
    ):
        try:
            result = handle_approve(
                pending_id=pending_id,
                registrations=container.registrations,
                bindings=container.bindings,
                server_domain=settings.server_domain,
            )
        except (PendingNotFoundError, ValueError) as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return JSONResponse(status_code=200, content=result)

    @app.post("/person/registrations/{pending_id}/deny", status_code=200)
    def deny_registration(
        pending_id: str,
        _person: Annotated[None, Depends(require_portal_person_api)],
        container: Annotated[ASContainer, Depends(get_container)],
    ):
        try:
            handle_deny(pending_id=pending_id, registrations=container.registrations)
        except PendingNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return Response(status_code=200)

    @app.post("/person/registrations/{pending_id}/link")
    def link_registration(
        pending_id: str,
        body: LinkBody,
        _person: Annotated[None, Depends(require_portal_person_api)],
        container: Annotated[ASContainer, Depends(get_container)],
    ):
        try:
            result = handle_link(
                pending_id=pending_id,
                target_agent_id=body.agent_id,
                registrations=container.registrations,
                bindings=container.bindings,
            )
        except (PendingNotFoundError, ASBindingNotFoundError, ValueError) as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except DuplicateStableKeyError:
            raise
        return JSONResponse(status_code=200, content=result)

    @app.get("/person/bindings")
    def list_bindings(
        _person: Annotated[None, Depends(require_portal_person_api)],
        container: Annotated[ASContainer, Depends(get_container)],
    ) -> list[dict[str, Any]]:
        return handle_list_bindings(container.bindings)

    @app.post("/person/bindings", status_code=201)
    def create_binding_from_stable_pub(
        body: RegisterBody,
        _person: Annotated[None, Depends(require_portal_person_api)],
        container: Annotated[ASContainer, Depends(get_container)],
        settings: Annotated[AgentServerSettings, Depends(get_as_settings)],
    ) -> JSONResponse:
        try:
            result = handle_create_binding_from_stable_pub(
                stable_pub=body.stable_pub,
                agent_name=body.agent_name,
                bindings=container.bindings,
                server_domain=settings.server_domain,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return JSONResponse(status_code=201, content=result)

    @app.post("/person/bindings/{agent_id}/revoke", status_code=200)
    def revoke_binding(
        agent_id: str,
        _person: Annotated[None, Depends(require_portal_person_api)],
        container: Annotated[ASContainer, Depends(get_container)],
    ):
        try:
            handle_revoke_binding(agent_id=agent_id, bindings=container.bindings)
        except (KeyError, ASBindingNotFoundError) as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return Response(status_code=200)

    static_dir = Path(__file__).resolve().parent.parent / "ui"
    if static_dir.is_dir():
        app.mount("/ui", StaticFiles(directory=str(static_dir), html=True), name="ui")

    return app


app = create_portal_app()
