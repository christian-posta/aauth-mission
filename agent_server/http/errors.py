"""AAuth-shaped JSON error responses."""

from __future__ import annotations

from typing import Any

from aauth import errors as aauth_errors
from fastapi.responses import JSONResponse


def aauth_json_error(
    status_code: int,
    error: str,
    error_description: str | None = None,
    **extras: Any,
) -> JSONResponse:
    body: dict[str, Any] = aauth_errors.build_error_response(error, error_description, **extras)
    return JSONResponse(status_code=status_code, content=body)
