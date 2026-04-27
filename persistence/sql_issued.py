"""SQL-backed store for issued auth tokens (audit log)."""

from __future__ import annotations

import base64
import json
import secrets
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy import select, desc

from persistence.models import PsIssuedTokenRow
from ps.service.issued_token_store import IssuedTokenStore


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    """Decode JWT payload without signature verification."""
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}


class DatabaseIssuedTokenStore(IssuedTokenStore):
    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def record_issued(
        self,
        *,
        auth_token: str,
        agent_id: str,
        owner_id: str | None,
        resource_iss: str | None,
        resource_scope: str | None,
        justification: str | None,
        issue_method: str,
        expires_at: datetime | None,
    ) -> None:
        payload = _decode_jwt_payload(auth_token)
        jti = payload.get("jti") or None
        if isinstance(jti, str) and not jti:
            jti = None

        row = PsIssuedTokenRow(
            issued_id=secrets.token_hex(16),
            agent_id=agent_id,
            owner_id=owner_id,
            resource_iss=resource_iss,
            resource_scope=resource_scope,
            justification=justification,
            issue_method=issue_method,
            token_jti=jti,
            expires_at=expires_at,
        )
        with self._session_factory() as s:
            s.add(row)
            s.commit()

    def list_issued(self) -> list[dict[str, Any]]:
        with self._session_factory() as s:
            rows = (
                s.execute(
                    select(PsIssuedTokenRow).order_by(desc(PsIssuedTokenRow.issued_at))
                )
                .scalars()
                .all()
            )
        return [
            {
                "issued_id": r.issued_id,
                "agent_id": r.agent_id,
                "owner_id": r.owner_id,
                "resource_iss": r.resource_iss,
                "resource_scope": r.resource_scope,
                "justification": r.justification,
                "issue_method": r.issue_method,
                "token_jti": r.token_jti,
                "issued_at": r.issued_at.isoformat() if r.issued_at else None,
                "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            }
            for r in rows
        ]
