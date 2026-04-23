"""Shared request body models for the Agent Server HTTP API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RegisterBody(BaseModel):
    """JSON body for ``POST /register`` and ``POST /person/bindings`` (stable key enrollment)."""

    model_config = ConfigDict(extra="forbid")

    stable_pub: dict[str, Any] = Field(
        ..., description="Agent's stable Ed25519 public key (JWK)"
    )
    agent_name: str = Field(
        ...,
        description="Human-readable name for the agent (shown in approval and binding UIs).",
    )

    @field_validator("agent_name")
    @classmethod
    def _normalize_agent_name(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("agent_name must be non-empty and not only whitespace")
        if len(s) > 256:
            raise ValueError("agent_name must be at most 256 characters after trimming")
        return s
