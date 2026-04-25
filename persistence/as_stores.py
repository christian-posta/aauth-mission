"""SQL-backed agent registration and binding stores."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_server.exceptions import DuplicateStableKeyError
from agent_server.models import Binding, PendingRegistration
from persistence.models import AsBindingJktRow, AsBindingRow, AsPendingRegistrationRow

SessionFactory = Callable[[], Session]


class SQLPendingRegistrationStore:
    def __init__(self, session_factory: SessionFactory, default_ttl: int = 3600) -> None:
        self._session_factory = session_factory
        self._default_ttl = default_ttl

    def create(
        self,
        stable_pub: dict[str, Any],
        ephemeral_pub: dict[str, Any],
        agent_name: str,
        stable_jkt: str,
        ttl_seconds: int | None = None,
    ) -> PendingRegistration:
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        now = datetime.now(timezone.utc)
        reg = PendingRegistration(
            id=secrets.token_urlsafe(16),
            stable_pub=stable_pub,
            ephemeral_pub=ephemeral_pub,
            agent_name=agent_name,
            stable_jkt=stable_jkt,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl),
            status="pending",
        )
        r = AsPendingRegistrationRow(
            id=reg.id,
            stable_pub=stable_pub,
            ephemeral_pub=ephemeral_pub,
            agent_name=reg.agent_name,
            stable_jkt=stable_jkt,
            created_at=reg.created_at,
            expires_at=reg.expires_at,
            status=reg.status,
        )
        with self._session_factory() as s:
            s.add(r)
            s.commit()
        return reg

    def get(self, pending_id: str) -> PendingRegistration | None:
        now = datetime.now(timezone.utc)
        with self._session_factory() as s:
            row = s.get(AsPendingRegistrationRow, pending_id)
            if row is None:
                return None
            if row.status == "pending" and now >= row.expires_at:
                row.status = "denied"
            s.commit()
            return self._row_to_reg(row)

    @staticmethod
    def _row_to_reg(row: AsPendingRegistrationRow) -> PendingRegistration:
        return PendingRegistration(
            id=row.id,
            stable_pub=dict(row.stable_pub) if isinstance(row.stable_pub, dict) else {},
            ephemeral_pub=dict(row.ephemeral_pub) if isinstance(row.ephemeral_pub, dict) else {},
            agent_name=row.agent_name,
            stable_jkt=row.stable_jkt,
            created_at=row.created_at,
            expires_at=row.expires_at,
            status=row.status,  # type: ignore[assignment,arg-type]
        )

    def approve(self, pending_id: str) -> None:
        with self._session_factory() as s:
            r = s.get(AsPendingRegistrationRow, pending_id)
            if r is None:
                raise KeyError(pending_id)
            r.status = "approved"
            s.commit()

    def deny(self, pending_id: str) -> None:
        with self._session_factory() as s:
            r = s.get(AsPendingRegistrationRow, pending_id)
            if r is None:
                raise KeyError(pending_id)
            r.status = "denied"
            s.commit()

    def list_pending(self) -> list[PendingRegistration]:
        now = datetime.now(timezone.utc)
        with self._session_factory() as s:
            rows = s.execute(
                select(AsPendingRegistrationRow).where(AsPendingRegistrationRow.status == "pending")
            ).scalars().all()
        result: list[PendingRegistration] = []
        for row in rows:
            reg = self._row_to_reg(row)
            if reg.status == "pending" and now >= reg.expires_at:
                with self._session_factory() as s2:
                    r2 = s2.get(AsPendingRegistrationRow, reg.id)
                    if r2 is not None:
                        r2.status = "denied"
                        s2.commit()
                continue
            if reg.status == "pending":
                result.append(reg)
        return sorted(result, key=lambda r: r.created_at)

    def find_by_stable_jkt(self, stable_jkt: str) -> PendingRegistration | None:
        now = datetime.now(timezone.utc)
        with self._session_factory() as s:
            row = s.execute(
                select(AsPendingRegistrationRow).where(
                    AsPendingRegistrationRow.stable_jkt == stable_jkt,
                    AsPendingRegistrationRow.status == "pending",
                )
            ).scalars().first()
        if row is None:
            return None
        reg = self._row_to_reg(row)
        if reg.status == "pending" and now >= reg.expires_at:
            with self._session_factory() as s2:
                r2 = s2.get(AsPendingRegistrationRow, reg.id)
                if r2 is not None:
                    r2.status = "denied"
                    s2.commit()
            return None
        return reg


class SQLBindingStore:
    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    @staticmethod
    def _row_to_binding(row: AsBindingRow) -> Binding:
        st = list(row.stable_key_thumbprints) if isinstance(row.stable_key_thumbprints, list) else []
        return Binding(
            agent_id=row.agent_id,
            agent_name=row.agent_name,
            created_at=row.created_at,
            stable_key_thumbprints=[str(x) for x in st],
            revoked=row.revoked,
        )

    def create(self, agent_id: str, agent_name: str, stable_jkt: str) -> Binding:
        binding = Binding(
            agent_id=agent_id,
            agent_name=agent_name,
            created_at=datetime.now(timezone.utc),
            stable_key_thumbprints=[stable_jkt],
            revoked=False,
        )
        with self._session_factory() as s:
            s.add(
                AsBindingRow(
                    agent_id=agent_id,
                    agent_name=agent_name,
                    created_at=binding.created_at,
                    stable_key_thumbprints=list(binding.stable_key_thumbprints),
                    revoked=False,
                )
            )
            s.add(AsBindingJktRow(stable_jkt=stable_jkt, agent_id=agent_id))
            s.commit()
        return binding

    def lookup_by_stable_jkt(self, jkt: str) -> Binding | None:
        with self._session_factory() as s:
            j = s.get(AsBindingJktRow, jkt)
            if j is None:
                return None
            row = s.get(AsBindingRow, j.agent_id)
        if row is None:
            return None
        return self._row_to_binding(row)

    def get_by_agent_id(self, agent_id: str) -> Binding | None:
        with self._session_factory() as s:
            row = s.get(AsBindingRow, agent_id)
        if row is None:
            return None
        return self._row_to_binding(row)

    def update_agent_name(self, agent_id: str, agent_name: str) -> None:
        with self._session_factory() as s:
            row = s.get(AsBindingRow, agent_id)
            if row is None:
                raise KeyError(agent_id)
            row.agent_name = agent_name.strip()
            s.commit()

    def list_all(self) -> list[Binding]:
        with self._session_factory() as s:
            rows = s.execute(select(AsBindingRow)).scalars().all()
        return sorted((self._row_to_binding(r) for r in rows), key=lambda b: b.created_at)

    def add_stable_key(self, agent_id: str, stable_jkt: str) -> None:
        with self._session_factory() as s:
            row = s.get(AsBindingRow, agent_id)
            if row is None:
                raise KeyError(agent_id)
            st = list(row.stable_key_thumbprints) if isinstance(row.stable_key_thumbprints, list) else []
            if stable_jkt in st:
                raise DuplicateStableKeyError(f"{stable_jkt} already on binding {agent_id}")
            st.append(stable_jkt)
            row.stable_key_thumbprints = st
            s.add(AsBindingJktRow(stable_jkt=stable_jkt, agent_id=agent_id))
            s.commit()

    def revoke(self, agent_id: str) -> None:
        with self._session_factory() as s:
            row = s.get(AsBindingRow, agent_id)
            if row is None:
                raise KeyError(agent_id)
            row.revoked = True
            s.commit()
