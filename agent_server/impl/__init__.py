"""In-memory reference implementations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Union

from agent_server.impl.memory_bindings import MemoryBindingStore
from agent_server.impl.memory_replay import ReplayCache
from agent_server.impl.memory_registrations import MemoryPendingRegistrationStore
from agent_server.service.signing import SigningService
from agent_server.service.token_factory import AgentTokenFactory


@dataclass
class ASContainer:
    registrations: Union[MemoryPendingRegistrationStore, "SQLPendingRegistrationStore"]
    bindings: Union[MemoryBindingStore, "SQLBindingStore"]
    replay: ReplayCache
    signing: SigningService
    token_factory: AgentTokenFactory


def build_memory_as(
    issuer: str,
    server_domain: str,
    signing_key_path: str | None,
    previous_key_path: str | None,
    agent_token_lifetime: int,
    registration_ttl: int,
    signature_window: int,
) -> ASContainer:
    signing = SigningService(
        issuer=issuer,
        server_domain=server_domain,
        signing_key_path=signing_key_path,
        previous_key_path=previous_key_path,
        agent_token_lifetime=agent_token_lifetime,
    )
    token_factory = AgentTokenFactory(signing=signing)
    registrations = MemoryPendingRegistrationStore(default_ttl=registration_ttl)
    bindings = MemoryBindingStore()
    replay = ReplayCache(window_seconds=signature_window)
    return ASContainer(
        registrations=registrations,
        bindings=bindings,
        replay=replay,
        signing=signing,
        token_factory=token_factory,
    )
