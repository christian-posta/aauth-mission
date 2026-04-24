"""Authentication dependencies: HWK / JWT HTTP message signatures + admin/user bearer tokens."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any, cast

import aauth
from fastapi import Depends, Header, HTTPException, Request

from aauth import errors as aauth_errors

from ps.exceptions import AgentTokenRejectError
from ps.http.config import PSHttpSettings
from ps.service.http_sig_auth import verify_agent_jwt_request


def get_settings(request: Request) -> PSHttpSettings:
    s = request.app.state.settings
    assert isinstance(s, PSHttpSettings)
    return s


def _hwk_thumbprint_from_parsed(parsed: dict[str, Any]) -> str:
    params = parsed.get("params") or {}
    if not params:
        raise HTTPException(status_code=401, detail="Could not parse public key from Signature-Key")
    jwk = dict(params)
    return aauth.calculate_jwk_thumbprint(jwk)


@dataclass(frozen=True, slots=True)
class TokenAgentContext:
    agent_id: str
    agent_jkt: str | None
    agent_cnf_jwk: dict[str, Any] | None
    secure_mode: bool


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

    parsed = aauth.parse_signature_key(sig_key)
    scheme = parsed.get("scheme")
    if scheme == "jwt":
        raise HTTPException(
            status_code=401,
            detail="Signature-Key scheme=jwt is not valid for this endpoint; use scheme=hwk",
        )
    if scheme != "hwk":
        raise HTTPException(
            status_code=401,
            detail=f"Signature-Key must use scheme=hwk for this Person Server (got {scheme!r})",
        )
    return _hwk_thumbprint_from_parsed(parsed)


async def require_token_agent(
    request: Request,
    settings: Annotated[PSHttpSettings, Depends(get_settings)],
) -> TokenAgentContext:
    """Context for ``POST /token``: ``scheme=jwt`` when secure; HWK / stub headers in insecure dev."""
    body = await request.body()
    ps = cast(Any, request.app.state.ps)
    target_uri = str(request.url)
    hdrs_orig = {k: v for k, v in request.headers.items()}

    if settings.insecure_dev:
        x_id = request.headers.get("X-AAuth-Agent-Id") or request.headers.get("x-aauth-agent-id")
        if x_id:
            return TokenAgentContext(
                agent_id=x_id,
                agent_jkt=None,
                agent_cnf_jwk=None,
                secure_mode=False,
            )
        sig_input = request.headers.get("signature-input")
        sig = request.headers.get("signature")
        sig_key = request.headers.get("signature-key")
        if sig_input and sig and sig_key:
            ok = aauth.verify_signature(
                method=request.method,
                target_uri=target_uri,
                headers=hdrs_orig,
                body=body,
                signature_input_header=sig_input,
                signature_header=sig,
                signature_key_header=sig_key,
            )
            if not ok:
                raise HTTPException(status_code=401, detail="HTTP signature verification failed")
            parsed = aauth.parse_signature_key(sig_key)
            if parsed.get("scheme") != "hwk":
                raise HTTPException(
                    status_code=401,
                    detail="Insecure dev token request: use scheme=hwk or X-AAuth-Agent-Id",
                )
            aid = _hwk_thumbprint_from_parsed(parsed)
            return TokenAgentContext(
                agent_id=aid,
                agent_jkt=None,
                agent_cnf_jwk=None,
                secure_mode=False,
            )
        raise HTTPException(
            status_code=401,
            detail="Insecure dev: send X-AAuth-Agent-Id or an HWK-signed request for POST /token",
        )

    sig_input = request.headers.get("signature-input")
    sig = request.headers.get("signature")
    sig_key = request.headers.get("signature-key")
    if not sig_input or not sig or not sig_key:
        raise AgentTokenRejectError(
            "Missing HTTP signature headers (Signature-Input, Signature, Signature-Key)",
            error=aauth_errors.ERROR_INVALID_SIGNATURE,
        )
    parsed = aauth.parse_signature_key(sig_key)
    if parsed.get("scheme") != "jwt":
        raise AgentTokenRejectError(
            "POST /token requires Signature-Key scheme=jwt when AAUTH_PS_INSECURE_DEV is false",
            error=aauth_errors.ERROR_INVALID_SIGNATURE,
        )

    try:
        va = verify_agent_jwt_request(
            method=request.method,
            target_uri=target_uri,
            headers=hdrs_orig,
            body=body,
            jwks_fetcher=ps.agent_jwks_resolver,
            insecure_dev=False,
        )
    except ValueError as e:
        msg = str(e).lower()
        if "agent token expired" in msg or "expiredsignature" in msg:
            raise AgentTokenRejectError(str(e), error=aauth_errors.ERROR_EXPIRED_AGENT_TOKEN) from e
        if (
            "http signature verification failed" in msg
            or "missing http signature" in msg
            or "signature-key must use scheme=jwt" in msg
        ):
            raise AgentTokenRejectError(str(e), error=aauth_errors.ERROR_INVALID_SIGNATURE) from e
        raise AgentTokenRejectError(str(e), error=aauth_errors.ERROR_INVALID_AGENT_TOKEN) from e

    return TokenAgentContext(
        agent_id=va.agent_id,
        agent_jkt=va.agent_jkt,
        agent_cnf_jwk=va.agent_cnf_jwk,
        secure_mode=True,
    )


def parse_prefer_wait(prefer: str | None) -> int | None:
    """Parse Prefer: wait=N (RFC 7240). Returns N or None."""
    if not prefer:
        return None
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
