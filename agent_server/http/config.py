"""Agent Server HTTP configuration (environment-driven)."""

from __future__ import annotations

import logging

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from agent_server.models import AgentServerMetadata

logger = logging.getLogger(__name__)


class AgentServerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AAUTH_AS_", env_file_encoding="utf-8")

    issuer: str = Field(
        default="https://agent-server.example",
        description="Public issuer URL. No trailing slash. Goes into agent token iss claim.",
    )
    server_domain: str = Field(
        default="agent-server.example",
        description="Domain used for the local part of aauth:<uuid>@<domain> agent IDs.",
    )
    public_origin: str = Field(
        default="http://localhost:8800",
        description="Public base URL (no trailing slash). Used to build endpoint URLs.",
    )

    signing_key_path: str | None = Field(
        default=None,
        description="Path to Ed25519 private key PEM file. Auto-generated if None or missing.",
    )
    previous_key_path: str | None = Field(
        default=None,
        description="Path to previous Ed25519 private key PEM for JWKS rotation transition.",
    )

    agent_token_lifetime: int = Field(
        default=86400,
        ge=60,
        le=86400,
        description="Agent token lifetime in seconds. Max 24h per spec.",
    )
    registration_ttl: int = Field(
        default=3600,
        ge=60,
        description="How long a pending registration stays open before expiring (seconds).",
    )
    signature_window: int = Field(
        default=60,
        ge=10,
        le=300,
        description="Allowed clock skew window for HTTP signature `created` parameter (seconds).",
    )

    client_name: str = Field(
        default="AAuth Agent Server",
        description="Human-readable name shown in well-known metadata.",
    )

    person_token: str = Field(
        default="changeme",
        description="Bearer token for /person/* endpoints.",
    )
    database_url: str | None = Field(
        default=None,
        description="If set, persist Agent Server registrations/bindings to this URL (shared with Person Server in Portal).",
    )
    insecure_dev: bool = Field(
        default=False,
        description="If true, skip HTTP signature verification (dev only).",
    )

    @model_validator(mode="after")
    def _warn_defaults(self) -> AgentServerSettings:
        if self.person_token == "changeme" and not self.insecure_dev:
            logger.warning(
                "AAUTH_AS_PERSON_TOKEN is set to the default value 'changeme'. "
                "Change it before exposing this server."
            )
        if not self.insecure_dev and self.public_origin.startswith("http://"):
            logger.warning(
                "AAUTH_AS_PUBLIC_ORIGIN uses http:// while INSECURE_DEV=false; "
                "spec requires HTTPS in production."
            )
        return self

    def metadata(self) -> AgentServerMetadata:
        o = self.public_origin.rstrip("/")
        return AgentServerMetadata(
            issuer=self.issuer,
            jwks_uri=f"{o}/.well-known/jwks.json",
            client_name=self.client_name,
            registration_endpoint=f"{o}/register",
            refresh_endpoint=f"{o}/refresh",
        )
