"""Verify HTTP Message Signatures with ``Signature-Key: sig=jwt`` (aa-agent+jwt)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import aauth
import jwt
from aauth import TokenError as AAuthTokenError
from aauth_signing.errors import SignatureError as HttpSigSignatureError


@dataclass(frozen=True, slots=True)
class VerifiedAgent:
    agent_id: str
    agent_cnf_jwk: dict[str, Any]
    agent_jkt: str
    agent_iss: str
    agent_token_jwt: str


def _extract_jwt_from_signature_key(parsed: dict[str, Any]) -> str:
    params = parsed.get("params") or {}
    jwt_str = params.get("jwt") if isinstance(params, dict) else None
    if not jwt_str and isinstance(parsed.get("jwt"), str):
        jwt_str = parsed["jwt"]
    if not jwt_str:
        raise ValueError("No JWT value in jwt Signature-Key")
    return str(jwt_str)


def verify_agent_jwt_request(
    *,
    method: str,
    target_uri: str,
    headers: dict[str, str],
    body: bytes,
    jwks_fetcher: Callable[[str], dict[str, Any] | None],
    insecure_dev: bool = False,
) -> VerifiedAgent:
    """Verify RFC 9421 signature and aa-agent+jwt in Signature-Key."""
    sig_input = headers.get("signature-input")
    sig = headers.get("signature")
    sig_key = headers.get("signature-key")
    if not sig_input or not sig or not sig_key:
        raise ValueError("Missing HTTP signature headers (Signature-Input, Signature, Signature-Key)")

    parsed = aauth.parse_signature_key(sig_key)
    if parsed.get("scheme") != "jwt":
        raise ValueError("Signature-Key must use scheme=jwt for this request")
    jwt_str = _extract_jwt_from_signature_key(parsed)

    try:
        claims = aauth.verify_agent_token(jwt_str, jwks_fetcher)
    except jwt.ExpiredSignatureError as e:
        raise ValueError(f"Agent token expired: {e}") from e
    except AAuthTokenError as e:
        raise ValueError(str(e)) from e

    if not insecure_dev:
        try:
            ok = aauth.verify_signature(
                method=method,
                target_uri=target_uri,
                headers=headers,
                body=body,
                signature_input_header=sig_input,
                signature_header=sig,
                signature_key_header=sig_key,
                jwks_fetcher=jwks_fetcher,
            )
        except HttpSigSignatureError as e:
            raise ValueError(str(e)) from e
        if not ok:
            raise ValueError("HTTP signature verification failed")

    iss = str(claims.get("iss", ""))
    sub = str(claims.get("sub", ""))
    cnf = claims.get("cnf") or {}
    eph = cnf.get("jwk")
    if not eph or not isinstance(eph, dict):
        raise ValueError("Agent token missing cnf.jwk")
    jkt = aauth.calculate_jwk_thumbprint(dict(eph))
    return VerifiedAgent(
        agent_id=sub,
        agent_cnf_jwk=dict(eph),
        agent_jkt=jkt,
        agent_iss=iss,
        agent_token_jwt=jwt_str,
    )
