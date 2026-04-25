"""SQL-backed ``AgentServerTrustRegistry`` (see ``ps.federation.agent_server_trust``)."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from persistence.models import PsTrustedAgentServerRow
from ps.federation.agent_server_trust import AgentServerTrustRegistry, TrustedAgentServer, normalize_issuer


def import_trust_from_file_if_empty(
    session_factory: Callable[[], Session],
    trust_file: str | None,
) -> None:
    if not trust_file:
        return
    path = Path(trust_file)
    if not path.exists():
        return
    with session_factory() as s:
        cnt = s.scalar(select(func.count()).select_from(PsTrustedAgentServerRow)) or 0
        if int(cnt) > 0:
            return
    raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    items = raw.get("trusted", [])
    with session_factory() as s:
        for it in items:
            e = TrustedAgentServer(
                issuer=normalize_issuer(str(it["issuer"])),
                display_name=str(it.get("display_name", "")),
                jwks_uri=str(it["jwks_uri"]),
                jwks_fingerprint=str(it["jwks_fingerprint"]),
                added_at=str(it.get("added_at", "")),
            )
            s.add(
                PsTrustedAgentServerRow(
                    issuer=e.issuer,
                    display_name=e.display_name,
                    jwks_uri=e.jwks_uri,
                    jwks_fingerprint=e.jwks_fingerprint,
                    added_at=e.added_at,
                )
            )
        s.commit()


class DatabaseAgentServerTrustRegistry(AgentServerTrustRegistry):
    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def list_trusted(self) -> list[TrustedAgentServer]:
        with self._session_factory() as s:
            rows = s.execute(select(PsTrustedAgentServerRow).order_by(PsTrustedAgentServerRow.issuer)).scalars().all()
        return [
            TrustedAgentServer(
                issuer=r.issuer,
                display_name=r.display_name,
                jwks_uri=r.jwks_uri,
                jwks_fingerprint=r.jwks_fingerprint,
                added_at=r.added_at,
            )
            for r in rows
        ]

    def add(self, entry: TrustedAgentServer) -> None:
        n = normalize_issuer(entry.issuer)
        with self._session_factory() as s:
            r = s.get(PsTrustedAgentServerRow, n)
            if r is None:
                s.add(
                    PsTrustedAgentServerRow(
                        issuer=n,
                        display_name=entry.display_name,
                        jwks_uri=entry.jwks_uri,
                        jwks_fingerprint=entry.jwks_fingerprint,
                        added_at=entry.added_at,
                    )
                )
            else:
                r.display_name = entry.display_name
                r.jwks_uri = entry.jwks_uri
                r.jwks_fingerprint = entry.jwks_fingerprint
                r.added_at = entry.added_at
            s.commit()

    def remove(self, issuer: str) -> bool:
        n = normalize_issuer(issuer)
        with self._session_factory() as s:
            r = s.get(PsTrustedAgentServerRow, n)
            if r is None:
                return False
            s.delete(r)
            s.commit()
        return True

    def is_trusted(self, issuer: str) -> bool:
        n = normalize_issuer(issuer)
        with self._session_factory() as s:
            r = s.get(PsTrustedAgentServerRow, n)
        return r is not None
