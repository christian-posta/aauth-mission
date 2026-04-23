"""In-memory PendingRegistrationStore."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from agent_server.models import PendingRegistration


class MemoryPendingRegistrationStore:
    def __init__(self, default_ttl: int = 3600) -> None:
        self._default_ttl = default_ttl
        self._store: dict[str, PendingRegistration] = {}

    def create(
        self,
        stable_pub: dict[str, Any],
        ephemeral_pub: dict[str, Any],
        label: str | None,
        stable_jkt: str,
        ttl_seconds: int | None = None,
    ) -> PendingRegistration:
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        now = datetime.now(timezone.utc)
        reg = PendingRegistration(
            id=secrets.token_urlsafe(16),
            stable_pub=stable_pub,
            ephemeral_pub=ephemeral_pub,
            label=label,
            stable_jkt=stable_jkt,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl),
            status="pending",
        )
        self._store[reg.id] = reg
        return reg

    def get(self, pending_id: str) -> PendingRegistration | None:
        reg = self._store.get(pending_id)
        if reg is None:
            return None
        # Auto-expire
        if reg.status == "pending" and datetime.now(timezone.utc) >= reg.expires_at:
            reg.status = "denied"
        return reg

    def approve(self, pending_id: str) -> None:
        reg = self._store.get(pending_id)
        if reg is None:
            raise KeyError(pending_id)
        reg.status = "approved"

    def deny(self, pending_id: str) -> None:
        reg = self._store.get(pending_id)
        if reg is None:
            raise KeyError(pending_id)
        reg.status = "denied"

    def list_pending(self) -> list[PendingRegistration]:
        now = datetime.now(timezone.utc)
        result = []
        for reg in self._store.values():
            if reg.status == "pending" and now >= reg.expires_at:
                reg.status = "denied"
            if reg.status == "pending":
                result.append(reg)
        return sorted(result, key=lambda r: r.created_at)

    def find_by_stable_jkt(self, stable_jkt: str) -> PendingRegistration | None:
        """Return an in-flight (pending) registration with this stable JKT, if any."""
        now = datetime.now(timezone.utc)
        for reg in self._store.values():
            if reg.stable_jkt == stable_jkt and reg.status == "pending":
                if now < reg.expires_at:
                    return reg
        return None
