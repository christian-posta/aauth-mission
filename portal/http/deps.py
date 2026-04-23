"""Portal-specific FastAPI dependencies (dual settings + unified person auth)."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request

from agent_server.exceptions import InvalidSignatureError
from agent_server.http.config import AgentServerSettings
from agent_server.impl import ASContainer
from agent_server.models import VerifiedRequest
from agent_server.service.http_sig import HttpSigVerifier
from ps.http.config import PSHttpSettings


def get_ps_settings(request: Request) -> PSHttpSettings:
    s = request.app.state.ps_settings
    assert isinstance(s, PSHttpSettings)
    return s


def get_as_settings(request: Request) -> AgentServerSettings:
    s = request.app.state.as_settings
    assert isinstance(s, AgentServerSettings)
    return s


def get_container(request: Request) -> ASContainer:
    c = request.app.state.container
    assert isinstance(c, ASContainer)
    return c


async def require_http_sig(
    request: Request,
    settings: Annotated[AgentServerSettings, Depends(get_as_settings)],
    container: Annotated[ASContainer, Depends(get_container)],
) -> VerifiedRequest:
    """Same as agent_server.http.deps.require_http_sig but uses portal app.state.as_settings."""
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


def require_portal_admin(
    ps_settings: Annotated[PSHttpSettings, Depends(get_ps_settings)],
    as_settings: Annotated[AgentServerSettings, Depends(get_as_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    """Replaces PS require_admin: open if admin_token unset; else Bearer admin or AS person token."""
    expected = ps_settings.admin_token
    if expected is None:
        return
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization: Bearer required")
    got = authorization.removeprefix("Bearer ").strip()
    if got != expected and got != as_settings.person_token:
        raise HTTPException(status_code=403, detail="Invalid admin token")


def require_portal_user_id(
    ps_settings: Annotated[PSHttpSettings, Depends(get_ps_settings)],
    as_settings: Annotated[AgentServerSettings, Depends(get_as_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    """Replaces PS require_user: portal accepts admin token, AS person token, or PS user_token."""
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization: Bearer required")
    got = authorization.removeprefix("Bearer ").strip()
    ut = ps_settings.user_token
    at = ps_settings.admin_token
    if ut is not None and got == ut:
        return ps_settings.user_id
    if at is not None and got == at:
        return ps_settings.user_id
    if got == as_settings.person_token:
        return ps_settings.user_id
    raise HTTPException(status_code=403, detail="Invalid user token")


def require_portal_person_api(
    ps_settings: Annotated[PSHttpSettings, Depends(get_ps_settings)],
    as_settings: Annotated[AgentServerSettings, Depends(get_as_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    """Replaces AS require_person: Bearer must match AS person token or PS admin token."""
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization: Bearer required")
    got = authorization.removeprefix("Bearer ").strip()
    if got == as_settings.person_token:
        return
    if ps_settings.admin_token is not None and got == ps_settings.admin_token:
        return
    raise HTTPException(status_code=403, detail="Invalid person token")
