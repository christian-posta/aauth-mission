"""Person-facing route logic: registration approval/denial/linking, binding management."""

from __future__ import annotations

from typing import Any

import aauth

from agent_server.exceptions import (
    BindingNotFoundError,
    DuplicateStableKeyError,
    PendingNotFoundError,
    StableKeyAlreadyBoundError,
)
from agent_server.impl.memory_bindings import MemoryBindingStore
from agent_server.impl.memory_registrations import MemoryPendingRegistrationStore
from agent_server.utils.agent_id import generate_agent_id


def handle_approve(
    pending_id: str,
    registrations: MemoryPendingRegistrationStore,
    bindings: MemoryBindingStore,
    server_domain: str,
) -> dict[str, Any]:
    """POST /person/registrations/{id}/approve.

    Creates the binding, then marks the pending registration as approved.
    """
    reg = registrations.get(pending_id)
    if reg is None:
        raise PendingNotFoundError(pending_id)
    if reg.status != "pending":
        raise ValueError(f"Registration {pending_id} is not pending (status={reg.status})")

    agent_id = generate_agent_id(server_domain)
    binding = bindings.create(
        agent_id=agent_id,
        agent_name=reg.agent_name,
        stable_jkt=reg.stable_jkt,
    )
    registrations.approve(pending_id)
    return {"agent_id": binding.agent_id, "agent_name": binding.agent_name}


def handle_deny(
    pending_id: str,
    registrations: MemoryPendingRegistrationStore,
) -> None:
    """POST /person/registrations/{id}/deny."""
    reg = registrations.get(pending_id)
    if reg is None:
        raise PendingNotFoundError(pending_id)
    registrations.deny(pending_id)


def handle_link(
    pending_id: str,
    target_agent_id: str,
    registrations: MemoryPendingRegistrationStore,
    bindings: MemoryBindingStore,
) -> dict[str, Any]:
    """POST /person/registrations/{id}/link — add device to existing binding.

    Adds the stable JKT from the pending registration to the target binding,
    then marks the pending registration as approved so the agent can poll for its token.
    """
    reg = registrations.get(pending_id)
    if reg is None:
        raise PendingNotFoundError(pending_id)
    if reg.status != "pending":
        raise ValueError(f"Registration {pending_id} is not pending (status={reg.status})")

    binding = bindings.get_by_agent_id(target_agent_id)
    if binding is None:
        raise BindingNotFoundError(target_agent_id)
    if binding.revoked:
        raise BindingNotFoundError(f"Binding {target_agent_id} is revoked")

    try:
        bindings.add_stable_key(target_agent_id, reg.stable_jkt)
    except DuplicateStableKeyError:
        raise

    registrations.approve(pending_id)
    return {"agent_id": binding.agent_id, "agent_name": reg.agent_name}


def handle_list_registrations(
    registrations: MemoryPendingRegistrationStore,
) -> list[dict[str, Any]]:
    """GET /person/registrations."""
    return [_reg_dict(r) for r in registrations.list_pending()]


def handle_list_bindings(bindings: MemoryBindingStore) -> list[dict[str, Any]]:
    """GET /person/bindings."""
    return [_binding_dict(b) for b in bindings.list_all()]


def handle_revoke_binding(
    agent_id: str,
    bindings: MemoryBindingStore,
) -> None:
    """POST /person/bindings/{agent_id}/revoke."""
    binding = bindings.get_by_agent_id(agent_id)
    if binding is None:
        raise BindingNotFoundError(agent_id)
    bindings.revoke(agent_id)


def handle_create_binding_from_stable_pub(
    stable_pub: dict[str, Any],
    agent_name: str,
    bindings: MemoryBindingStore,
    server_domain: str,
) -> dict[str, Any]:
    """POST /person/bindings — trust a stable public JWK without a pending registration.

    The agent still obtains an ``agent_token`` by calling ``POST /register`` with HTTP
    signatures (immediate issuance once this binding exists).
    """
    try:
        stable_jkt = f"urn:jkt:sha-256:{aauth.calculate_jwk_thumbprint(stable_pub)}"
    except Exception as exc:
        raise ValueError("Invalid stable_pub JWK") from exc

    existing = bindings.lookup_by_stable_jkt(stable_jkt)
    if existing is not None and not existing.revoked:
        raise StableKeyAlreadyBoundError(existing.agent_id)

    agent_id = generate_agent_id(server_domain)
    binding = bindings.create(agent_id=agent_id, agent_name=agent_name, stable_jkt=stable_jkt)
    return {
        "agent_id": binding.agent_id,
        "agent_name": binding.agent_name,
        "stable_jkt": stable_jkt,
    }


# ------------------------------------------------------------------
# Serialisation helpers
# ------------------------------------------------------------------

def _reg_dict(r: Any) -> dict[str, Any]:
    return {
        "id": r.id,
        "agent_name": r.agent_name,
        "stable_jkt": r.stable_jkt,
        "created_at": r.created_at.isoformat(),
        "expires_at": r.expires_at.isoformat(),
        "status": r.status,
    }


def _binding_dict(b: Any) -> dict[str, Any]:
    return {
        "agent_id": b.agent_id,
        "agent_name": b.agent_name,
        "created_at": b.created_at.isoformat(),
        "device_count": len(b.stable_key_thumbprints),
        "stable_key_thumbprints": b.stable_key_thumbprints,
        "revoked": b.revoked,
    }
