"""Authentication dependencies: HWK HTTP message signatures + admin/user bearer tokens."""

from __future__ import annotations

import logging
from typing import Annotated

import aauth
from fastapi import Depends, Header, HTTPException, Request

from ps.http.config import PSHttpSettings

logger = logging.getLogger(__name__)


def get_settings(request: Request) -> PSHttpSettings:
    s = request.app.state.settings
    assert isinstance(s, PSHttpSettings)
    return s


def _agent_id_from_signature_key(signature_key_header: str) -> str:
    """Pseudonymous agent id: JWK thumbprint of the HWK public key (RFC 7638)."""
    parsed = aauth.parse_signature_key(signature_key_header)
    if parsed.get("scheme") != "hwk":
        raise HTTPException(
            status_code=401,
            detail="Signature-Key must use scheme=hwk for this Person Server",
        )
    params = parsed.get("params") or {}
    if not params:
        raise HTTPException(status_code=401, detail="Could not parse public key from Signature-Key")
    jwk = dict(params)
    return aauth.calculate_jwk_thumbprint(jwk)


async def require_agent_id(
    request: Request,
    settings: Annotated[PSHttpSettings, Depends(get_settings)],
    x_aauth_agent_id: Annotated[str | None, Header(alias="X-AAuth-Agent-Id")] = None,
) -> str:
    if settings.insecure_dev:
        if x_aauth_agent_id:
            return x_aauth_agent_id
        raise HTTPException(
            status_code=401,
            detail="X-AAuth-Agent-Id required when AAUTH_PS_INSECURE_DEV enables stub agent identification",
        )

    sig_input = request.headers.get("signature-input")
    sig = request.headers.get("signature")
    sig_key = request.headers.get("signature-key")
    if not sig_input or not sig or not sig_key:
        raise HTTPException(
            status_code=401,
            detail="Missing HTTP signature headers (Signature-Input, Signature, Signature-Key)",
        )

    body = await request.body()
    target_uri = str(request.url)
    hdrs = {k: v for k, v in request.headers.items()}

    ok = aauth.verify_signature(
        method=request.method,
        target_uri=target_uri,
        headers=hdrs,
        body=body,
        signature_input_header=sig_input,
        signature_header=sig,
        signature_key_header=sig_key,
    )
    if not ok:
        raise HTTPException(status_code=401, detail="HTTP signature verification failed")

    return _agent_id_from_signature_key(sig_key)


def parse_prefer_wait(prefer: str | None) -> int | None:
    """Parse Prefer: wait=N (RFC 7240). Returns N or None."""
    if not prefer:
        return None
    # e.g. "wait=45" or "respond-async, wait=30"
    for part in prefer.split(","):
        part = part.strip()
        if part.lower().startswith("wait="):
            try:
                return int(part.split("=", 1)[1].strip())
            except ValueError:
                return None
    return None


def require_admin(
    settings: Annotated[PSHttpSettings, Depends(get_settings)],
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


def require_user(
    settings: Annotated[PSHttpSettings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    expected = settings.user_token
    if expected is None:
        raise HTTPException(
            status_code=503,
            detail="Legal user API not configured (set AAUTH_PS_USER_TOKEN)",
        )
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization: Bearer required")
    got = authorization.removeprefix("Bearer ").strip()
    if got != expected:
        raise HTTPException(status_code=403, detail="Invalid user token")
    return settings.user_id
