"""HTTP server configuration (environment-driven)."""

from __future__ import annotations

import logging

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from ps.models import PSMetadata

logger = logging.getLogger(__name__)


class PSHttpSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AAUTH_PS_", env_file_encoding="utf-8")

    public_origin: str = Field(
        default="http://localhost:8765",
        description="Public base URL of this Person Server (no trailing slash). Use the same host you open in the browser (e.g. localhost vs 127.0.0.1) so AAuth-Requirement URLs match.",
    )
    insecure_dev: bool = Field(
        default=True,
        description="If true, agent routes accept X-AAuth-Agent-Id without verifying HTTP message signatures.",
    )
    admin_token: str | None = Field(
        default=None,
        description="If set, require Authorization: Bearer <token> for /missions.",
    )
    user_token: str | None = Field(
        default=None,
        description="Bearer token for legal-user routes (/user/missions, /user/consent).",
    )
    user_id: str = Field(
        default="user",
        description="Subject id returned by require_user when user_token matches.",
    )
    require_user_session: bool = Field(
        default=False,
        description="Reserved: require user session for /interaction (not enforced in simple mode).",
    )
    auto_approve_token: bool = Field(
        default=False,
        description="If true, skip consent on POST /token. If false (secure mode), consent is required only when "
        "the verified resource token scope includes the require:user scope (space-separated); otherwise the auth "
        "token is issued immediately.",
    )
    auto_approve_mission: bool = Field(
        default=True,
        description="If false, POST /mission returns 202 pending until user approves via interaction flow.",
    )
    jwks_uri: str | None = Field(
        default=None,
        description="Override JWKS URI in metadata; default is {origin}/.well-known/jwks.json",
    )
    agent_jwt_stub: str = Field(
        default="stub-agent-jwt",
        description="Placeholder agent JWT string passed to FakeASFederator.",
    )
    pending_ttl_seconds: int = Field(
        default=600,
        ge=1,
        description="TTL for open pending rows before expired/abandoned (protocol pending URL security).",
    )
    signing_key_path: str | None = Field(
        default=".aauth/ps-signing-key.pem",
        description="PS Ed25519 signing key PEM. Generated on first boot if missing. Empty string = ephemeral in-memory key.",
    )
    trust_file: str | None = Field(
        default=".aauth/ps-trusted-agents.json",
        description="JSON file for trusted agent-server registry (UI-managed). Empty string disables persistence.",
    )
    auth_token_lifetime: int = Field(
        default=3600,
        ge=60,
        le=3600,
        description="Lifetime in seconds for PS-issued aa-auth+jwt (SPEC max 1 hour).",
    )
    database_url: str | None = Field(
        default=None,
        description="If set, persist PS state to this SQLAlchemy URL (SQLite, PostgreSQL, etc.).",
    )

    @field_validator("signing_key_path", mode="before")
    @classmethod
    def _signing_path_empty_ephemeral(cls, v: object) -> object:
        if v == "":
            return None
        return v

    @field_validator("trust_file", mode="before")
    @classmethod
    def _trust_file_empty(cls, v: object) -> object:
        if v == "":
            return None
        return v

    @model_validator(mode="after")
    def warn_https_when_not_insecure_dev(self) -> PSHttpSettings:
        if not self.insecure_dev and self.public_origin.startswith("http://"):
            logger.warning(
                "AAUTH_PS_PUBLIC_ORIGIN uses http:// while INSECURE_DEV=false; "
                "spec requires interaction URLs to use https in production."
            )
        return self

    def metadata(self) -> PSMetadata:
        o = self.public_origin.rstrip("/")
        jwks = self.jwks_uri or f"{o}/.well-known/jwks.json"
        return PSMetadata(
            issuer=o,
            token_endpoint=f"{o}/token",
            mission_endpoint=f"{o}/mission",
            permission_endpoint=f"{o}/permission",
            audit_endpoint=f"{o}/audit",
            interaction_endpoint=f"{o}/interaction",
            mission_control_endpoint=f"{o}/missions",
            jwks_uri=jwks,
        )
