"""Well-known metadata and JWKS endpoints."""

from __future__ import annotations

from typing import Any


def well_known_agent_payload(
    issuer: str,
    jwks_uri: str,
    client_name: str,
    registration_endpoint: str,
    refresh_endpoint: str,
) -> dict[str, Any]:
    return {
        "issuer": issuer,
        "jwks_uri": jwks_uri,
        "client_name": client_name,
        "registration_endpoint": registration_endpoint,
        "refresh_endpoint": refresh_endpoint,
    }
