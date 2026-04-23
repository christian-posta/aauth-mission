"""Refresh (token renewal) route logic."""

from __future__ import annotations

from typing import Any

from agent_server.exceptions import BindingNotFoundError, BindingRevokedError, InvalidSignatureError
from agent_server.impl.memory_bindings import MemoryBindingStore
from agent_server.models import VerifiedRequest
from agent_server.service.token_factory import AgentTokenFactory


def handle_refresh(
    verified: VerifiedRequest,
    bindings: MemoryBindingStore,
    token_factory: AgentTokenFactory,
) -> dict[str, Any]:
    """POST /refresh handler logic.

    The HTTP signature was verified by the dependency (including full jkt-jwt chain).
    Here we just look up the binding by stable JKT and issue a new token.
    """
    if verified.scheme != "jkt-jwt":
        raise InvalidSignatureError(
            f"Refresh requires jkt-jwt Signature-Key scheme, got {verified.scheme!r}"
        )

    stable_jkt = verified.stable_jkt
    if not stable_jkt:
        raise InvalidSignatureError("No stable JKT in verified request")

    binding = bindings.lookup_by_stable_jkt(stable_jkt)
    if binding is None:
        raise BindingNotFoundError(f"No binding found for stable key {stable_jkt}")
    if binding.revoked:
        raise BindingRevokedError(f"Binding {binding.agent_id} has been revoked")

    token = token_factory.issue(
        agent_id=binding.agent_id,
        ephemeral_pub=verified.ephemeral_pub,
    )
    return {"agent_token": token}
