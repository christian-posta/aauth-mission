"""FastAPI application exposing the MM REST API (plan Layer 4 + draft-hardt-aauth-protocol)."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Response
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
from mm.exceptions import ForbiddenOwnerError, NotFoundError, PendingDeniedError, PendingGoneError
from mm.http.config import MMHttpSettings
from mm.http.deps import get_settings, require_admin, require_agent_id, require_user
from mm.http.encoding import (
    auth_token_http_dict,
    build_aauth_requirement_header,
    consent_context_http_dict,
    deferred_body_dict,
    mission_http_dict,
    mission_state_from_query,
)
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
        agent_jwt_stub=settings.agent_jwt_stub,
    )

    app = FastAPI(
        title="AAuth Mission Manager",
        version="0.1.0",
        description="Simple in-memory MM REST API (draft-hardt-aauth-protocol).",
    )
    app.state.settings = settings
    app.state.mm = mm

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
    def post_mission(
        body: MissionProposalBody,
        agent_id: Annotated[str, Depends(require_agent_id)],
    ):
        proposal = MissionProposal(
            agent_id=agent_id,
            proposal_text=body.mission_proposal,
            owner_hint=body.owner_hint,
        )
        out = create_mission_route(mm.lifecycle, proposal)
        return _mission_outcome_response(out)

    @app.post("/token")
    def post_token(
        body: TokenRequestBody,
        agent_id: Annotated[str, Depends(require_agent_id)],
    ):
        req = TokenRequest(
            agent_id=agent_id,
            resource_token=body.resource_token,
            justification=body.justification,
            upstream_token=body.upstream_token,
            login_hint=body.login_hint,
            tenant=body.tenant,
            domain_hint=body.domain_hint,
        )
        out = request_token_route(mm.token_broker, req)
        return _token_outcome_response(out)

    @app.get("/pending/{pending_id}")
    def get_pending(pending_id: str):
        try:
            out = get_pending_route(mm.token_broker, pending_id)
        except NotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        except PendingGoneError:
            raise HTTPException(status_code=410, detail="gone") from None
        except PendingDeniedError as e:
            raise HTTPException(status_code=403, detail=e.reason) from e
        return _token_outcome_response(out)

    @app.post("/pending/{pending_id}")
    def post_pending(pending_id: str, body: PendingPostBody, agent_id: Annotated[str, Depends(require_agent_id)]):
        _ = agent_id
        if body.clarification_response is not None:
            b: ClarificationPostBody | UpdatedTokenPostBody = ClarificationPostBody(
                clarification_response=body.clarification_response
            )
        else:
            b = UpdatedTokenPostBody(resource_token=body.resource_token or "", justification=body.justification)
        out = post_pending_route(mm.token_broker, pending_id, b)
        return _token_outcome_response(out)

    @app.delete("/pending/{pending_id}", status_code=204)
    def delete_pending(pending_id: str, agent_id: Annotated[str, Depends(require_agent_id)]):
        _ = agent_id
        try:
            cancel_pending_route(mm.token_broker, pending_id)
        except NotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e

    @app.get("/interaction")
    def get_interaction(code: str, settings: Annotated[MMHttpSettings, Depends(get_settings)]):
        if settings.require_user_session:
            pass
        try:
            ctx = get_interaction_route(mm.user_consent, code)
            mm.user_consent.mark_interacting(ctx.pending_id)
        except NotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        return consent_context_http_dict(ctx)

    @app.post("/interaction/{pending_id}/decision")
    def post_decision(pending_id: str, body: UserDecisionBody):
        decision = UserDecision(
            approved=body.approved,
            clarification_question=body.clarification_question,
        )
        try:
            post_decision_route(mm.user_consent, pending_id, decision)
        except NotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        return Response(status_code=204)

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
            raise HTTPException(status_code=403, detail="not owner of this mission") from None
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
            raise HTTPException(status_code=403, detail="not owner of this mission") from None
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
