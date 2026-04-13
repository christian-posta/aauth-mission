"""FastAPI application exposing the MM REST API (plan Layer 4 + draft-hardt-aauth-protocol)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated, Any

from aauth import errors as aauth_errors
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, model_validator

from mm.api.agent_routes import (
    ClarificationPostBody,
    UpdatedTokenPostBody,
    cancel_pending_route,
    create_mission_route,
    get_pending_route,
    post_pending_route,
    request_token_route,
)
from mm.api.admin_routes import get_mission_route, list_missions_route, patch_mission
from mm.api.metadata import get_mm_metadata
from mm.api.user_mission_routes import (
    get_user_mission_route,
    list_user_missions_route,
    patch_user_mission_route,
    user_consent_queue,
)
from mm.api.user_routes import get_interaction_route, post_decision_route
from mm.exceptions import (
    ClarificationLimitError,
    ForbiddenOwnerError,
    InvalidInteractionCodeError,
    NotFoundError,
    PendingDeniedError,
    PendingExpiredError,
    PendingGoneError,
    SlowDownError,
)
from mm.http.config import MMHttpSettings
from mm.http.deps import get_settings, parse_prefer_wait, require_admin, require_agent_id, require_user
from mm.http.encoding import (
    auth_token_http_dict,
    build_aauth_requirement_header,
    consent_context_http_dict,
    deferred_body_dict,
    mission_http_dict,
    mission_state_from_query,
)
from mm.http.errors import aauth_json_error
from mm.impl import MMContainer, build_memory_mm
from mm.models import (
    AuthTokenResponse,
    DeferredResponse,
    Mission,
    MissionProposal,
    MissionState,
    TokenRequest,
    UserDecision,
)
from mm.utils.sanitize import sanitize_markdown_input

logger = logging.getLogger(__name__)


class MissionProposalBody(BaseModel):
    mission_proposal: str = Field(..., description="Markdown mission text per protocol")
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


class MissionPatchBody(BaseModel):
    state: MissionState


def _is_agent_protocol_path(path: str) -> bool:
    return path.startswith("/mission") or path.startswith("/token") or path.startswith("/pending")


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


def _token_outcome_response(out: AuthTokenResponse | DeferredResponse | Mission) -> JSONResponse:
    if isinstance(out, AuthTokenResponse):
        return JSONResponse(auth_token_http_dict(out))
    if isinstance(out, Mission):
        return JSONResponse({"mission": mission_http_dict(out)})
    return _json_deferred(out)


def _mission_outcome_response(out: Mission | DeferredResponse) -> JSONResponse:
    if isinstance(out, Mission):
        return JSONResponse({"mission": mission_http_dict(out)})
    return _json_deferred(out)


def _mission_list_item(m: Mission) -> dict[str, Any]:
    return {
        "s256": m.s256,
        "approved": m.approved_text,
        "state": m.state.value,
        "agent_id": m.agent_id,
        "created_at": m.created_at.isoformat(),
        "owner_id": m.owner_id,
    }


def _mission_detail(m: Mission) -> dict[str, Any]:
    return {
        "mission": mission_http_dict(m),
        "state": m.state.value,
        "agent_id": m.agent_id,
        "created_at": m.created_at.isoformat(),
        "owner_id": m.owner_id,
    }


def create_app(settings: MMHttpSettings | None = None) -> FastAPI:
    settings = settings or MMHttpSettings()
    mm: MMContainer = build_memory_mm(
        public_origin=settings.public_origin,
        auto_approve_token=settings.auto_approve_token,
        auto_approve_mission=settings.auto_approve_mission,
        agent_jwt_stub=settings.agent_jwt_stub,
        pending_ttl_seconds=settings.pending_ttl_seconds,
    )

    app = FastAPI(
        title="AAuth Mission Manager",
        version="0.1.0",
        description="Simple in-memory MM REST API (draft-hardt-aauth-protocol).",
    )
    app.state.settings = settings
    app.state.mm = mm

    @app.exception_handler(InvalidInteractionCodeError)
    async def invalid_interaction_code_handler(
        _request: Request, _exc: InvalidInteractionCodeError
    ) -> JSONResponse:
        return aauth_json_error(
            410,
            aauth_errors.ERROR_INVALID_CODE,
            "interaction code not recognized or already consumed",
        )

    @app.exception_handler(NotFoundError)
    async def not_found_handler(_request: Request, exc: NotFoundError) -> JSONResponse:
        msg = str(exc) or "not found"
        return aauth_json_error(404, aauth_errors.ERROR_INVALID_REQUEST, msg)

    @app.exception_handler(PendingGoneError)
    async def gone_handler(_request: Request, _exc: PendingGoneError) -> JSONResponse:
        return aauth_json_error(410, aauth_errors.ERROR_INVALID_CODE, "pending request was cancelled")

    @app.exception_handler(PendingDeniedError)
    async def denied_handler(_request: Request, exc: PendingDeniedError) -> JSONResponse:
        reason = exc.reason
        if reason == "abandoned":
            return aauth_json_error(403, aauth_errors.ERROR_ABANDONED, "user did not complete interaction")
        if reason == "denied":
            return aauth_json_error(403, aauth_errors.ERROR_DENIED, "request was denied")
        return aauth_json_error(403, aauth_errors.ERROR_DENIED, reason)

    @app.exception_handler(PendingExpiredError)
    async def expired_handler(_request: Request, _exc: PendingExpiredError) -> JSONResponse:
        return aauth_json_error(408, aauth_errors.ERROR_EXPIRED, "pending request expired")

    @app.exception_handler(SlowDownError)
    async def slow_handler(_request: Request, _exc: SlowDownError) -> JSONResponse:
        return aauth_json_error(429, aauth_errors.ERROR_SLOW_DOWN, "polling too frequently")

    @app.exception_handler(ClarificationLimitError)
    async def clar_limit_handler(_request: Request, _exc: ClarificationLimitError) -> JSONResponse:
        return aauth_json_error(
            400,
            aauth_errors.ERROR_INVALID_REQUEST,
            "clarification round limit exceeded",
        )

    @app.exception_handler(ForbiddenOwnerError)
    async def forbidden_owner_handler(_request: Request, _exc: ForbiddenOwnerError) -> JSONResponse:
        return aauth_json_error(403, aauth_errors.ERROR_DENIED, "not owner of this mission")

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        if _is_agent_protocol_path(request.url.path):
            return aauth_json_error(400, aauth_errors.ERROR_INVALID_REQUEST, str(exc))
        return JSONResponse(status_code=422, content={"detail": exc.errors()})

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        if exc.status_code == 401 and _is_agent_protocol_path(request.url.path):
            desc = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
            return aauth_json_error(401, aauth_errors.ERROR_INVALID_SIGNATURE, desc)
        if exc.status_code == 401:
            return JSONResponse(status_code=401, content={"detail": exc.detail})
        if exc.status_code == 403 and request.url.path.startswith("/user"):
            return JSONResponse(status_code=403, content={"detail": exc.detail})
        if exc.status_code == 403:
            return JSONResponse(status_code=403, content={"detail": exc.detail})
        if exc.status_code == 503:
            return JSONResponse(status_code=503, content={"detail": exc.detail})
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    @app.get("/.well-known/aauth-mission.json")
    def well_known():
        meta = get_mm_metadata(settings.metadata())
        return {
            "manager": meta.manager,
            "token_endpoint": meta.token_endpoint,
            "mission_endpoint": meta.mission_endpoint,
            "mission_control_endpoint": meta.mission_control_endpoint,
            "jwks_uri": meta.jwks_uri,
        }

    @app.get("/.well-known/jwks.json")
    def jwks_placeholder():
        return {"keys": []}

    @app.post("/mission")
    async def post_mission(
        body: MissionProposalBody,
        request: Request,
        agent_id: Annotated[str, Depends(require_agent_id)],
    ):
        prefer = parse_prefer_wait(request.headers.get("prefer"))
        if prefer is not None:
            logger.debug("POST /mission Prefer: wait=%s (long-poll not implemented)", prefer)
        proposal = MissionProposal(
            agent_id=agent_id,
            proposal_text=sanitize_markdown_input(body.mission_proposal),
            owner_hint=body.owner_hint,
        )
        out = create_mission_route(mm.lifecycle, proposal)
        return _mission_outcome_response(out)

    @app.post("/token")
    async def post_token(
        body: TokenRequestBody,
        request: Request,
        agent_id: Annotated[str, Depends(require_agent_id)],
    ):
        prefer = parse_prefer_wait(request.headers.get("prefer"))
        if prefer is not None:
            logger.debug("POST /token Prefer: wait=%s (long-poll not implemented)", prefer)
        just = sanitize_markdown_input(body.justification) if body.justification else None
        req = TokenRequest(
            agent_id=agent_id,
            resource_token=body.resource_token,
            justification=just,
            upstream_token=body.upstream_token,
            login_hint=body.login_hint,
            tenant=body.tenant,
            domain_hint=body.domain_hint,
        )
        out = request_token_route(mm.token_broker, req)
        return _token_outcome_response(out)

    @app.get("/pending/{pending_id}")
    async def get_pending(
        pending_id: str,
        request: Request,
        agent_id: Annotated[str, Depends(require_agent_id)],
    ):
        prefer = parse_prefer_wait(request.headers.get("prefer"))
        if prefer is not None:
            logger.debug("GET /pending Prefer: wait=%s (long-poll not implemented)", prefer)
        out = get_pending_route(mm.token_broker, pending_id, agent_id)
        return _token_outcome_response(out)

    @app.post("/pending/{pending_id}")
    async def post_pending(
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
            out = post_pending_route(mm.token_broker, pending_id, agent_id, b)
        except ClarificationLimitError:
            raise ClarificationLimitError() from None
        return _token_outcome_response(out)

    @app.delete("/pending/{pending_id}", status_code=204)
    async def delete_pending(pending_id: str, agent_id: Annotated[str, Depends(require_agent_id)]):
        cancel_pending_route(mm.token_broker, pending_id, agent_id)

    @app.get("/interaction")
    def get_interaction(
        code: str,
        settings: Annotated[MMHttpSettings, Depends(get_settings)],
        callback: str | None = None,
    ):
        if settings.require_user_session:
            pass
        ctx = get_interaction_route(mm.user_consent, code)
        mm.pending_store.set_callback_url(ctx.pending_id, callback)
        mm.user_consent.mark_interacting(ctx.pending_id)
        return consent_context_http_dict(ctx)

    @app.post("/interaction/{pending_id}/decision")
    def post_decision(pending_id: str, body: UserDecisionBody):
        decision = UserDecision(
            approved=body.approved,
            clarification_question=body.clarification_question,
        )
        try:
            result = post_decision_route(mm.user_consent, pending_id, decision)
        except NotFoundError as e:
            raise NotFoundError(str(e)) from e
        payload: dict[str, Any] = {}
        if result.redirect_url:
            payload["redirect_url"] = result.redirect_url
        return JSONResponse(status_code=200, content=payload)

    @app.get("/missions")
    def list_missions(
        _admin: Annotated[None, Depends(require_admin)],
        agent_id: str | None = None,
        state: str | None = None,
    ) -> list[dict[str, Any]]:
        st = mission_state_from_query(state)
        missions = list_missions_route(mm.mission_control, agent_id, st)
        return [_mission_list_item(m) for m in missions]

    @app.get("/missions/{s256}")
    def inspect_mission(s256: str, _admin: Annotated[None, Depends(require_admin)]):
        try:
            m = get_mission_route(mm.mission_control, s256)
        except NotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        return _mission_detail(m)

    @app.patch("/missions/{s256}")
    def patch_mission_route(s256: str, body: MissionPatchBody, _admin: Annotated[None, Depends(require_admin)]):
        try:
            m = patch_mission(mm.mission_control, s256, body.state)
        except NotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return _mission_detail(m)

    @app.get("/user/missions")
    def list_user_missions(user_id: Annotated[str, Depends(require_user)]) -> list[dict[str, Any]]:
        missions = list_user_missions_route(mm.mission_control, user_id)
        return [_mission_list_item(m) for m in missions]

    @app.get("/user/missions/{s256}")
    def inspect_user_mission(s256: str, user_id: Annotated[str, Depends(require_user)]):
        try:
            m = get_user_mission_route(mm.mission_control, s256, user_id)
        except NotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        except ForbiddenOwnerError:
            raise
        return _mission_detail(m)

    @app.patch("/user/missions/{s256}")
    def patch_user_mission_http(
        s256: str, body: MissionPatchBody, user_id: Annotated[str, Depends(require_user)]
    ):
        try:
            m = patch_user_mission_route(mm.mission_control, s256, user_id, body.state)
        except NotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        except ForbiddenOwnerError:
            raise
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return _mission_detail(m)

    @app.get("/user/consent")
    def list_user_consent(user_id: Annotated[str, Depends(require_user)]) -> list[dict[str, Any]]:
        return user_consent_queue(mm.pending_store, user_id)

    @app.get("/admin/pending")
    def admin_list_pending(_admin: Annotated[None, Depends(require_admin)]) -> list[dict[str, Any]]:
        """All open pending token/mission flows (admin console)."""
        return mm.pending_store.list_open_pending_for_admin()

    static_dir = Path(__file__).resolve().parent / "static"
    if static_dir.is_dir():
        app.mount("/ui", StaticFiles(directory=str(static_dir), html=True), name="ui")

    return app


app = create_app()
