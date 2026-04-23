"""FastAPI application for the AAuth Agent Server."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated, Any

from aauth import errors as aauth_errors
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from agent_server.api.metadata import well_known_agent_payload
from agent_server.api.person_routes import (
    handle_approve,
    handle_deny,
    handle_link,
    handle_list_bindings,
    handle_list_registrations,
    handle_revoke_binding,
)
from agent_server.api.refresh_routes import handle_refresh
from agent_server.api.registration_routes import handle_poll_pending, handle_register
from agent_server.exceptions import (
    BindingNotFoundError,
    BindingRevokedError,
    DuplicateStableKeyError,
    InvalidSignatureError,
    PendingDeniedError,
    PendingExpiredError,
    PendingNotFoundError,
)
from agent_server.http.config import AgentServerSettings
from agent_server.http.deps import get_container, get_settings, require_http_sig, require_person
from agent_server.http.errors import aauth_json_error
from agent_server.impl import ASContainer, build_memory_as
from agent_server.models import VerifiedRequest

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Request body models
# ------------------------------------------------------------------

class RegisterBody(BaseModel):
    stable_pub: dict[str, Any] = Field(..., description="Agent's stable Ed25519 public key (JWK)")
    label: str | None = Field(default=None, description="Human-readable device label")


class LinkBody(BaseModel):
    agent_id: str = Field(..., description="Existing binding agent_id to link this device into")


# ------------------------------------------------------------------
# App factory
# ------------------------------------------------------------------

def create_agent_app(settings: AgentServerSettings | None = None) -> FastAPI:
    settings = settings or AgentServerSettings()
    container: ASContainer = build_memory_as(
        issuer=settings.issuer,
        server_domain=settings.server_domain,
        signing_key_path=settings.signing_key_path,
        previous_key_path=settings.previous_key_path,
        agent_token_lifetime=settings.agent_token_lifetime,
        registration_ttl=settings.registration_ttl,
        signature_window=settings.signature_window,
    )

    app = FastAPI(
        title="AAuth Agent Server",
        version="0.1.0",
        description="AAuth Agent Server reference implementation — Path B (direct registration + stable key renewal).",
    )
    app.state.settings = settings
    app.state.container = container

    meta = settings.metadata()

    # ------------------------------------------------------------------
    # Exception handlers
    # ------------------------------------------------------------------

    @app.exception_handler(InvalidSignatureError)
    async def invalid_sig_handler(_req: Request, exc: InvalidSignatureError) -> JSONResponse:
        return aauth_json_error(401, aauth_errors.ERROR_INVALID_SIGNATURE, str(exc))

    @app.exception_handler(PendingNotFoundError)
    async def pending_not_found_handler(_req: Request, exc: PendingNotFoundError) -> JSONResponse:
        return aauth_json_error(404, aauth_errors.ERROR_INVALID_REQUEST, str(exc))

    @app.exception_handler(PendingDeniedError)
    async def pending_denied_handler(_req: Request, _exc: PendingDeniedError) -> JSONResponse:
        return JSONResponse(status_code=403, content={"error": "denied"})

    @app.exception_handler(PendingExpiredError)
    async def pending_expired_handler(_req: Request, _exc: PendingExpiredError) -> JSONResponse:
        return JSONResponse(status_code=410, content={"error": "expired"})

    @app.exception_handler(BindingNotFoundError)
    async def binding_not_found_handler(_req: Request, exc: BindingNotFoundError) -> JSONResponse:
        return aauth_json_error(404, aauth_errors.ERROR_INVALID_REQUEST, str(exc))

    @app.exception_handler(BindingRevokedError)
    async def binding_revoked_handler(_req: Request, exc: BindingRevokedError) -> JSONResponse:
        return aauth_json_error(401, aauth_errors.ERROR_INVALID_REQUEST, str(exc))

    @app.exception_handler(DuplicateStableKeyError)
    async def dup_key_handler(_req: Request, exc: DuplicateStableKeyError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"error": "conflict", "detail": str(exc)})

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_req: Request, exc: RequestValidationError) -> JSONResponse:
        return aauth_json_error(400, aauth_errors.ERROR_INVALID_REQUEST, str(exc))

    @app.exception_handler(HTTPException)
    async def http_exc_handler(_req: Request, exc: HTTPException) -> JSONResponse:
        if exc.status_code == 401:
            return aauth_json_error(401, aauth_errors.ERROR_INVALID_SIGNATURE, str(exc.detail))
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    # ------------------------------------------------------------------
    # Well-known endpoints
    # ------------------------------------------------------------------

    @app.get("/.well-known/aauth-agent.json")
    def well_known_agent() -> dict[str, Any]:
        return well_known_agent_payload(
            issuer=meta.issuer,
            jwks_uri=meta.jwks_uri,
            client_name=meta.client_name,
            registration_endpoint=meta.registration_endpoint,
            refresh_endpoint=meta.refresh_endpoint,
        )

    @app.get("/.well-known/jwks.json")
    def jwks() -> dict[str, Any]:
        return container.signing.get_jwks()

    # ------------------------------------------------------------------
    # Agent-facing: registration
    # ------------------------------------------------------------------

    @app.post("/register", status_code=202)
    async def post_register(
        body: RegisterBody,
        verified: Annotated[VerifiedRequest, Depends(require_http_sig)],
        container: Annotated[ASContainer, Depends(get_container)],
        settings: Annotated[AgentServerSettings, Depends(get_settings)],
    ):
        result = handle_register(
            verified=verified,
            stable_pub=body.stable_pub,
            label=body.label,
            registrations=container.registrations,
            bindings=container.bindings,
            token_factory=container.token_factory,
            server_domain=settings.server_domain,
        )
        if result["immediate"]:
            return JSONResponse(status_code=200, content={"agent_token": result["agent_token"]})

        pending_id = result["pending_id"]
        expires_at = result["expires_at"]
        location = f"{settings.public_origin}/pending/{pending_id}"
        return JSONResponse(
            status_code=202,
            content={"status": "pending", "expires_at": expires_at.isoformat()},
            headers={
                "Location": f"/pending/{pending_id}",
                "Retry-After": "5",
                "Cache-Control": "no-store",
            },
        )

    @app.get("/pending/{pending_id}")
    async def get_pending(
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

    # ------------------------------------------------------------------
    # Agent-facing: refresh
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Person-facing: registration management
    # ------------------------------------------------------------------

    @app.get("/person/registrations")
    def list_registrations(
        _person: Annotated[None, Depends(require_person)],
        container: Annotated[ASContainer, Depends(get_container)],
    ) -> list[dict[str, Any]]:
        return handle_list_registrations(container.registrations)

    @app.post("/person/registrations/{pending_id}/approve")
    def approve_registration(
        pending_id: str,
        _person: Annotated[None, Depends(require_person)],
        container: Annotated[ASContainer, Depends(get_container)],
        settings: Annotated[AgentServerSettings, Depends(get_settings)],
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
        _person: Annotated[None, Depends(require_person)],
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
        _person: Annotated[None, Depends(require_person)],
        container: Annotated[ASContainer, Depends(get_container)],
    ):
        try:
            result = handle_link(
                pending_id=pending_id,
                target_agent_id=body.agent_id,
                registrations=container.registrations,
                bindings=container.bindings,
            )
        except (PendingNotFoundError, BindingNotFoundError, ValueError) as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except DuplicateStableKeyError as exc:
            raise
        return JSONResponse(status_code=200, content=result)

    # ------------------------------------------------------------------
    # Person-facing: binding management
    # ------------------------------------------------------------------

    @app.get("/person/bindings")
    def list_bindings(
        _person: Annotated[None, Depends(require_person)],
        container: Annotated[ASContainer, Depends(get_container)],
    ) -> list[dict[str, Any]]:
        return handle_list_bindings(container.bindings)

    @app.post("/person/bindings/{agent_id}/revoke", status_code=200)
    def revoke_binding(
        agent_id: str,
        _person: Annotated[None, Depends(require_person)],
        container: Annotated[ASContainer, Depends(get_container)],
    ):
        try:
            handle_revoke_binding(agent_id=agent_id, bindings=container.bindings)
        except (KeyError, BindingNotFoundError) as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return Response(status_code=200)

    # ------------------------------------------------------------------
    # Static UI
    # ------------------------------------------------------------------

    static_dir = Path(__file__).resolve().parent.parent / "ui"
    if static_dir.is_dir():
        app.mount("/ui", StaticFiles(directory=str(static_dir), html=True), name="ui")

    return app


app = create_agent_app()
