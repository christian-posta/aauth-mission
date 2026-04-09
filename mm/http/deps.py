"""Authentication dependencies (stubs aligned with plan: signatures + admin bearer)."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request

from mm.http.config import MMHttpSettings


def get_settings(request: Request) -> MMHttpSettings:
    s = request.app.state.settings
    assert isinstance(s, MMHttpSettings)
    return s


def require_agent_id(
    request: Request,
    settings: Annotated[MMHttpSettings, Depends(get_settings)],
    x_aauth_agent_id: Annotated[str | None, Header(alias="X-AAuth-Agent-Id")] = None,
) -> str:
    if settings.insecure_dev:
        if x_aauth_agent_id:
            return x_aauth_agent_id
        raise HTTPException(
            status_code=401,
            detail="X-AAuth-Agent-Id required when AAUTH_MM_INSECURE_DEV enables stub agent identification",
        )
    for name in ("signature-input", "signature", "signature-key"):
        if request.headers.get(name) is None:
            raise HTTPException(status_code=401, detail=f"Missing HTTP signature header: {name}")
    if not x_aauth_agent_id:
        raise HTTPException(
            status_code=401,
            detail="Signature verification is not implemented; set X-AAuth-Agent-Id after enabling verification.",
        )
    return x_aauth_agent_id


def require_admin(
    settings: Annotated[MMHttpSettings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    expected = settings.admin_token
    if expected is None:
        return
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization: Bearer required")
    got = authorization.removeprefix("Bearer ").strip()
    if got != expected:
        raise HTTPException(status_code=403, detail="Invalid admin token")
