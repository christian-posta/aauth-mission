"""SQL-backed MissionStatePort."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import datetime
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from persistence.models import PsMissionLogRow, PsMissionRow
from ps.models import MissionLogKind
from ps.impl.mission_state import MissionStatePort
from ps.models import Mission, MissionLogEntry, MissionState


def _row_to_mission(r: PsMissionRow) -> Mission:
    at = r.approved_tools
    at_t: tuple[dict[str, str], ...] | None
    if at is None:
        at_t = None
    else:
        at_t = tuple(dict(x) for x in cast(list[Any], at))
    caps = r.capabilities
    return Mission(
        s256=r.s256,
        blob_bytes=bytes(r.blob_bytes),
        state=MissionState(r.state),
        agent_id=r.agent_id,
        owner_id=r.owner_id,
        approver=r.approver,
        description=r.description,
        approved_at=r.approved_at,
        approved_tools=at_t,
        capabilities=tuple(caps) if caps is not None else None,  # type: ignore[arg-type]
    )


def _mission_to_row(m: Mission) -> PsMissionRow:
    at: Any = None
    if m.approved_tools is not None:
        at = [dict(t) for t in m.approved_tools]
    cap: Any = None
    if m.capabilities is not None:
        cap = list(m.capabilities)
    return PsMissionRow(
        s256=m.s256,
        blob_bytes=m.blob_bytes,
        state=m.state.value,
        agent_id=m.agent_id,
        owner_id=m.owner_id,
        approver=m.approver,
        description=m.description,
        approved_at=m.approved_at,
        approved_tools=at,
        capabilities=cap,
    )


class SqlMissionState:
    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def get_mission(self, s256: str) -> Mission | None:
        with self._session_factory() as s:
            r = s.get(PsMissionRow, s256)
            if r is None:
                return None
            return _row_to_mission(r)

    def set_mission(self, m: Mission) -> None:
        with self._session_factory() as s:
            row = s.get(PsMissionRow, m.s256)
            n = _mission_to_row(m)
            if row is None:
                s.add(n)
            else:
                row.blob_bytes = n.blob_bytes
                row.state = n.state
                row.agent_id = n.agent_id
                row.owner_id = n.owner_id
                row.approver = n.approver
                row.description = n.description
                row.approved_at = n.approved_at
                row.approved_tools = n.approved_tools
                row.capabilities = n.capabilities
            s.commit()

    def has_mission(self, s256: str) -> bool:
        with self._session_factory() as s:
            r = s.get(PsMissionRow, s256)
            return r is not None

    def iter_missions(self) -> Iterator[Mission]:
        with self._session_factory() as s:
            rows = s.scalars(select(PsMissionRow)).all()
            for r in rows:
                yield _row_to_mission(r)

    def append_mission_log(self, s256: str, entry: MissionLogEntry) -> None:
        with self._session_factory() as s:
            s.add(
                PsMissionLogRow(
                    s256=s256,
                    ts=entry.ts,
                    kind=entry.kind.value,
                    payload=entry.payload,
                )
            )
            s.commit()

    def get_mission_log(self, s256: str) -> list[MissionLogEntry]:
        with self._session_factory() as s:
            q = select(PsMissionLogRow).where(PsMissionLogRow.s256 == s256).order_by(PsMissionLogRow.id)
            rows = s.scalars(q).all()
        return [
            MissionLogEntry(
                ts=cast(Any, r.ts),
                kind=MissionLogKind(r.kind),
                payload=dict(r.payload) if isinstance(r.payload, dict) else {},
            )
            for r in rows
        ]
