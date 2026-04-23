"""FastAPI dependency injection for the Agent Server."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request

from agent_server.exceptions import InvalidSignatureError
from agent_server.http.config import AgentServerSettings
from agent_server.impl import ASContainer
from agent_server.models import VerifiedRequest
from agent_server.service.http_sig import HttpSigVerifier

logger = logging.getLogger(__name__)


def get_settings(request: Request) -> AgentServerSettings:
    s = request.app.state.settings
    assert isinstance(s, AgentServerSettings)
    return s


def get_container(request: Request) -> ASContainer:
    c = request.app.state.container
    assert isinstance(c, ASContainer)
    return c


async def require_http_sig(
    request: Request,
    settings: Annotated[AgentServerSettings, Depends(get_settings)],
    container: Annotated[ASContainer, Depends(get_container)],
) -> VerifiedRequest:
    """Verify HTTP Message Signature on agent-facing requests."""
    body = await request.body()
    target_uri = str(request.url)
    hdrs = {k.lower(): v for k, v in request.headers.items()}

    verifier = HttpSigVerifier(replay=container.replay, insecure_dev=settings.insecure_dev)
    try:
        return verifier.verify(
            method=request.method,
            target_uri=target_uri,
            headers=hdrs,
            body=body,
        )
    except InvalidSignatureError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


def require_person(
    settings: Annotated[AgentServerSettings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    """Validate Authorization: Bearer <person_token> for /person/* endpoints."""
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization: Bearer required")
    got = authorization.removeprefix("Bearer ").strip()
    if got != settings.person_token:
        raise HTTPException(status_code=403, detail="Invalid person token")
