"""Reference in-memory implementations for development and tests."""

from __future__ import annotations

from dataclasses import dataclass

from mm.federation.as_federator import ASFederator
from mm.impl.backend import MMBackend
from mm.impl.fake_federator import FakeASFederator
from mm.impl.memory_consent import MemoryUserConsent
from mm.impl.memory_control import MemoryMissionControl
from mm.impl.memory_lifecycle import MemoryMissionLifecycle
from mm.impl.memory_pending import MemoryPendingStore
from mm.impl.memory_token import MemoryTokenBroker
from mm.service.mission_control import MissionControl
from mm.service.mission_lifecycle import MissionLifecycle
from mm.service.token_broker import TokenBroker
from mm.service.user_consent import UserConsent


@dataclass(frozen=True, slots=True)
class MMContainer:
    backend: MMBackend
    pending_store: MemoryPendingStore
    federator: ASFederator
    lifecycle: MissionLifecycle
    token_broker: TokenBroker
    user_consent: UserConsent
    mission_control: MissionControl


def build_memory_mm(
    *,
    public_origin: str,
    auto_approve_token: bool = False,
    agent_jwt_stub: str = "stub-agent-jwt",
) -> MMContainer:
    """Wire in-memory stores and fake AS federation into the MM service interfaces."""
    backend = MMBackend()
    origin = public_origin.rstrip("/")
    store = MemoryPendingStore(backend, interaction_base_url=origin)
    federator = FakeASFederator()
    lifecycle = MemoryMissionLifecycle(backend)
    token_broker = MemoryTokenBroker(
        store,
        federator,
        agent_jwt_stub=agent_jwt_stub,
        auto_approve_without_consent=auto_approve_token,
    )
    consent = MemoryUserConsent(
        backend,
        store,
        federator,
        agent_jwt_stub=agent_jwt_stub,
    )
    control = MemoryMissionControl(backend)
    return MMContainer(
        backend=backend,
        pending_store=store,
        federator=federator,
        lifecycle=lifecycle,
        token_broker=token_broker,
        user_consent=consent,
        mission_control=control,
    )
