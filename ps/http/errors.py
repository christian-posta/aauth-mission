"""Spec-shaped JSON error responses (draft-hardt-aauth-protocol §Token Endpoint Error Response Format).

Structured ``error`` codes for Person Server token flows use :mod:`aauth.errors`, including:

- ``invalid_resource_token`` / ``expired_resource_token`` — :exc:`ps.exceptions.ResourceTokenRejectError`
- ``invalid_agent_token`` / ``expired_agent_token`` / ``invalid_signature`` —
  :exc:`ps.exceptions.AgentTokenRejectError` on secure ``POST /token``
"""

from __future__ import annotations

from typing import Any

from fastapi.responses import JSONResponse

from aauth import errors as aauth_errors

__all__ = ["aauth_errors", "aauth_json_error"]


def aauth_json_error(status_code: int, error: str, error_description: str | None = None, **extras: Any) -> JSONResponse:
    body: dict[str, Any] = aauth_errors.build_error_response(error, error_description, **extras)
    return JSONResponse(status_code=status_code, content=body)
