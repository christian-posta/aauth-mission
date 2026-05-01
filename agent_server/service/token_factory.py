"""AgentTokenFactory — thin wrapper around aauth.create_agent_token()."""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from agent_server.service.signing import SigningService


class AgentTokenFactory:
    def __init__(self, signing: SigningService) -> None:
        self._signing = signing

    def issue(
        self,
        agent_id: str,
        ephemeral_pub: dict[str, Any],
        lifetime_seconds: int | None = None,
    ) -> str:
        """Create and sign an agent token JWT."""
        return self._signing.create_agent_token(
            agent_id=agent_id,
            ephemeral_pub=ephemeral_pub,
            lifetime_seconds=lifetime_seconds,
        )
