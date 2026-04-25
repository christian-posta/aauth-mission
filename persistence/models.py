"""SQLAlchemy ORM models for the unified AAuth database."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, LargeBinary, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import JSON
from sqlalchemy.orm import Mapped, mapped_column

from persistence.base import Base


# JSON: uses JSONB on PostgreSQL, generic JSON on SQLite
def _json_type():
    return JSON().with_variant(JSONB, "postgresql")


class PsMissionRow(Base):
    __tablename__ = "ps_mission"

    s256: Mapped[str] = mapped_column(String(128), primary_key=True)
    blob_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(512), nullable=False)
    owner_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    approver: Mapped[str] = mapped_column(String(1024), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    approved_tools: Mapped[object | None] = mapped_column(_json_type(), nullable=True)
    capabilities: Mapped[object | None] = mapped_column(_json_type(), nullable=True)


class PsMissionLogRow(Base):
    __tablename__ = "ps_mission_log"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    s256: Mapped[str] = mapped_column(
        String(128), ForeignKey("ps_mission.s256", ondelete="CASCADE"), nullable=False, index=True
    )
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[object] = mapped_column(_json_type(), nullable=False)


class PsPendingRow(Base):
    __tablename__ = "ps_pending"

    pending_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    interaction_code: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    owner_id: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    rec_kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    requirement: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    gone: Mapped[bool] = mapped_column(default=False, nullable=False)
    code_unusable: Mapped[bool] = mapped_column(default=False, nullable=False)
    is_open: Mapped[bool] = mapped_column(default=True, nullable=False, index=True)
    data: Mapped[object] = mapped_column(_json_type(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class PsTrustedAgentServerRow(Base):
    __tablename__ = "ps_trusted_agent_server"

    issuer: Mapped[str] = mapped_column(String(1024), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    jwks_uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    jwks_fingerprint: Mapped[str] = mapped_column(String(256), nullable=False)
    added_at: Mapped[str] = mapped_column(String(64), default="", nullable=False)


class AsPendingRegistrationRow(Base):
    __tablename__ = "as_pending_registration"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    stable_pub: Mapped[object] = mapped_column(_json_type(), nullable=False)
    ephemeral_pub: Mapped[object] = mapped_column(_json_type(), nullable=False)
    agent_name: Mapped[str] = mapped_column(String(512), nullable=False)
    stable_jkt: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)


class AsBindingRow(Base):
    __tablename__ = "as_binding"

    agent_id: Mapped[str] = mapped_column(String(512), primary_key=True)
    agent_name: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    stable_key_thumbprints: Mapped[object] = mapped_column(_json_type(), nullable=False)
    revoked: Mapped[bool] = mapped_column(default=False, nullable=False)


class AsBindingJktRow(Base):
    __tablename__ = "as_binding_jkt"

    stable_jkt: Mapped[str] = mapped_column(String(256), primary_key=True)
    agent_id: Mapped[str] = mapped_column(
        String(512), ForeignKey("as_binding.agent_id", ondelete="CASCADE"), nullable=False, index=True
    )
