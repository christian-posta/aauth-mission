"""Interface for recording issued auth tokens."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any


class IssuedTokenStore(ABC):
    @abstractmethod
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
        """Persist a record of an issued auth token."""

    @abstractmethod
    def list_issued(self) -> list[dict[str, Any]]:
        """Return all issued token records, newest first."""
