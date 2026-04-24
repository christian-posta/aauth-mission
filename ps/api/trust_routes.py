"""Admin API: trusted agent-server issuers (runtime registry)."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from ps.federation.agent_server_trust import (
    AgentServerTrustRegistry,
    TrustedAgentServer,
    normalize_issuer,
)
from ps.federation.sync_http import fetch_json


class TrustedAgentIn(BaseModel):
    issuer: str = Field(..., description="Agent server issuer URL (HTTPS), e.g. https://as.example")
    display_name: str = Field(default="", description="Optional label for the admin UI")


def _jwks_fingerprint(jwks: dict[str, object]) -> str:
    return hashlib.sha256(json.dumps(jwks, sort_keys=True).encode("utf-8")).hexdigest()


def handle_list_trusted(registry: AgentServerTrustRegistry, *, ps_origin: str) -> list[dict[str, object]]:
    origin = normalize_issuer(ps_origin)
    rows: list[dict[str, object]] = [
        {
            "issuer": origin,
            "display_name": "This deployment (implicit trust when agent token iss matches)",
            "jwks_uri": f"{origin}/.well-known/jwks.json",
            "jwks_fingerprint": None,
            "implicit": True,
            "added_at": None,
        }
    ]
    for e in registry.list_trusted():
        rows.append(
            {
                "issuer": e.issuer,
                "display_name": e.display_name,
                "jwks_uri": e.jwks_uri,
                "jwks_fingerprint": e.jwks_fingerprint,
                "implicit": False,
                "added_at": e.added_at,
            }
        )
    return rows


def handle_add_trusted(registry: AgentServerTrustRegistry, body: TrustedAgentIn) -> TrustedAgentServer:
    iss = normalize_issuer(body.issuer)
    meta_url = f"{iss}/.well-known/aauth-agent.json"
    meta = fetch_json(meta_url)
    jwks_uri = meta.get("jwks_uri")
    if not jwks_uri or not isinstance(jwks_uri, str):
        raise ValueError(f"No jwks_uri in metadata from {meta_url}")
    jwks = fetch_json(jwks_uri)
    if not isinstance(jwks.get("keys"), list):
        raise ValueError(f"Invalid JWKS from {jwks_uri}")
    fp = _jwks_fingerprint(jwks)
    entry = TrustedAgentServer(
        issuer=iss,
        display_name=(body.display_name.strip() or iss),
        jwks_uri=jwks_uri,
        jwks_fingerprint=fp,
        added_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    )
    registry.add(entry)
    return entry


def handle_remove_trusted(registry: AgentServerTrustRegistry, issuer: str) -> bool:
    return registry.remove(issuer)
