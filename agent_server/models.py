"""Data models for the AAuth Agent Server."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal


@dataclass
class PendingRegistration:
    id: str
    stable_pub: dict[str, Any]       # JWK of the agent's stable public key
    ephemeral_pub: dict[str, Any]    # JWK of the agent's ephemeral public key
    label: str | None                # Human-readable name from the agent
    stable_jkt: str                  # urn:jkt:sha-256:<thumbprint>
    created_at: datetime
    expires_at: datetime
    status: Literal["pending", "approved", "denied"]


@dataclass
class Binding:
    agent_id: str                            # aauth:<uuid>@<domain>
    label: str | None
    created_at: datetime
    stable_key_thumbprints: list[str] = field(default_factory=list)  # urn:jkt:sha-256:...
    revoked: bool = False


@dataclass
class VerifiedRequest:
    """Result of HTTP signature verification."""
    scheme: str                      # "hwk" or "jkt-jwt"
    ephemeral_pub: dict[str, Any]    # the key that signed the HTTP request
    stable_jkt: str | None = None    # only for jkt-jwt: urn:jkt:sha-256:<thumbprint>


@dataclass
class AgentServerMetadata:
    issuer: str
    jwks_uri: str
    client_name: str
    registration_endpoint: str
    refresh_endpoint: str
