"""In-memory IssuedTokenStore (dev / tests)."""

from __future__ import annotations

import base64
import json
import secrets
from datetime import datetime, timezone
from typing import Any

from ps.service.issued_token_store import IssuedTokenStore


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}


class MemoryIssuedTokenStore(IssuedTokenStore):
    def __init__(self) -> None:
        self._records: list[dict[str, Any]] = []

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
        now = datetime.now(tz=timezone.utc)
        self._records.append(
            {
                "issued_id": secrets.token_hex(16),
                "agent_id": agent_id,
                "owner_id": owner_id,
                "resource_iss": resource_iss,
                "resource_scope": resource_scope,
                "justification": justification,
                "issue_method": issue_method,
                "token_jti": jti,
                "issued_at": now.isoformat(),
                "expires_at": expires_at.isoformat() if expires_at else None,
            }
        )

    def list_issued(self) -> list[dict[str, Any]]:
        return list(reversed(self._records))
