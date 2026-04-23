"""Registration and pending poll route logic."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import aauth

from agent_server.exceptions import (
    BindingNotFoundError,
    InvalidSignatureError,
    PendingDeniedError,
    PendingExpiredError,
    PendingNotFoundError,
)
from agent_server.impl.memory_bindings import MemoryBindingStore
from agent_server.impl.memory_registrations import MemoryPendingRegistrationStore
from agent_server.models import Binding, PendingRegistration, VerifiedRequest
from agent_server.service.token_factory import AgentTokenFactory
from agent_server.utils.agent_id import generate_agent_id


def handle_register(
    verified: VerifiedRequest,
    stable_pub: dict[str, Any],
    agent_name: str,
    registrations: MemoryPendingRegistrationStore,
    bindings: MemoryBindingStore,
    token_factory: AgentTokenFactory,
    server_domain: str,
) -> dict[str, Any]:
    """POST /register handler logic.

    Returns either:
      {"immediate": True, "agent_token": "<jwt>"}   — known device, token issued immediately
      {"immediate": False, "pending_id": "<id>", "expires_at": <datetime>}  — queued for approval
    """
    stable_jkt = f"urn:jkt:sha-256:{aauth.calculate_jwk_thumbprint(stable_pub)}"

    # Re-registration of a known device — issue token immediately, no approval needed
    existing = bindings.lookup_by_stable_jkt(stable_jkt)
    if existing is not None and not existing.revoked:
        bindings.update_agent_name(existing.agent_id, agent_name)
        token = token_factory.issue(
            agent_id=existing.agent_id,
            ephemeral_pub=verified.ephemeral_pub,
        )
        return {"immediate": True, "agent_token": token}

    # New device — create a pending registration for person approval
    reg = registrations.create(
        stable_pub=stable_pub,
        ephemeral_pub=verified.ephemeral_pub,
        agent_name=agent_name,
        stable_jkt=stable_jkt,
    )
    return {"immediate": False, "pending_id": reg.id, "expires_at": reg.expires_at}


def handle_poll_pending(
    pending_id: str,
    verified: VerifiedRequest,
    registrations: MemoryPendingRegistrationStore,
    bindings: MemoryBindingStore,
    token_factory: AgentTokenFactory,
) -> dict[str, Any]:
    """GET /pending/{id} handler logic.

    Returns:
      {"status": "pending"}
      {"agent_token": "<jwt>"}
      raises PendingDeniedError | PendingExpiredError | PendingNotFoundError
    """
    reg = registrations.get(pending_id)
    if reg is None:
        raise PendingNotFoundError(pending_id)

    # Verify the polling agent is using the same ephemeral key as at registration
    _verify_ephemeral_continuity(verified, reg)

    if reg.status == "pending":
        now = datetime.now(timezone.utc)
        if now >= reg.expires_at:
            raise PendingExpiredError(pending_id)
        return {"status": "pending"}

    if reg.status == "denied":
        raise PendingDeniedError(pending_id)

    # status == "approved" — binding was created at approval time; look it up
    binding = bindings.lookup_by_stable_jkt(reg.stable_jkt)
    if binding is None or binding.revoked:
        raise BindingNotFoundError(f"Binding for {reg.stable_jkt} not found after approval")

    token = token_factory.issue(
        agent_id=binding.agent_id,
        ephemeral_pub=reg.ephemeral_pub,
    )
    return {"agent_token": token}


def _verify_ephemeral_continuity(verified: VerifiedRequest, reg: PendingRegistration) -> None:
    """Ensure the polling request is signed with the same ephemeral key used at registration."""
    registered_x = reg.ephemeral_pub.get("x")
    presented_x = verified.ephemeral_pub.get("x")
    if registered_x != presented_x:
        raise InvalidSignatureError(
            "Polling request must be signed with the same ephemeral key used at registration"
        )
