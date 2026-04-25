"""Reference in-memory implementations for development and tests."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Union

from ps.federation.agent_jwks import AgentServerJWKSResolver
from ps.federation.agent_server_trust import AgentServerTrustRegistry, MemoryAgentServerTrustRegistry
from ps.federation.as_federator import ASFederator
from ps.federation.resource_jwks import ResourceJWKSFetcher, ResourceJWKSResolver
from ps.impl.backend import PSBackend
from ps.impl.mission_state import MissionStatePort
from ps.impl.fake_federator import FakeASFederator
from ps.impl.memory_consent import MemoryUserConsent
from ps.impl.memory_control import MemoryMissionControl
from ps.impl.memory_lifecycle import MemoryMissionLifecycle
from ps.impl.memory_pending import MemoryPendingStore
from ps.impl.memory_token import MemoryTokenBroker
from ps.impl.ps_governance import PsGovernance
from ps.service.auth_issuer import AuthTokenIssuer
from ps.service.mission_control import MissionControl
from ps.service.mission_lifecycle import MissionLifecycle
from ps.service.signing import PSSigningService
from ps.service.token_broker import TokenBroker
from ps.service.user_consent import UserConsent


@dataclass(frozen=True, slots=True)
class PSContainer:
    """Mission and mission log state. In memory mode this is a ``PSBackend``; SQL mode uses ``SqlMissionState``."""

    mission: MissionStatePort
    pending_store: Union[MemoryPendingStore, "DatabasePendingStore"]
    federator: ASFederator
    lifecycle: MissionLifecycle
    token_broker: TokenBroker
    user_consent: UserConsent
    mission_control: MissionControl
    governance: PsGovernance
    ps_signing: PSSigningService
    trust_registry: AgentServerTrustRegistry
    agent_jwks_resolver: AgentServerJWKSResolver
    resource_jwks_resolver: ResourceJWKSResolver
    auth_issuer: AuthTokenIssuer


def build_memory_ps(
    *,
    public_origin: str,
    auto_approve_token: bool = False,
    auto_approve_mission: bool = True,
    agent_jwt_stub: str = "stub-agent-jwt",
    pending_ttl_seconds: int = 600,
    signing_key_path: str | None = ".aauth/ps-signing-key.pem",
    trust_file: str | None = ".aauth/ps-trusted-agents.json",
    auth_token_lifetime: int = 3600,
    user_id: str = "user",
    insecure_dev: bool = False,
    self_jwks_provider: Callable[[], dict[str, Any]] | None = None,
    resource_jwks: ResourceJWKSFetcher | None = None,
) -> PSContainer:
    """Wire in-memory stores, PS signing, trust registry, and token broker."""
    backend = PSBackend()
    origin = public_origin.rstrip("/")
    store = MemoryPendingStore(
        backend,
        interaction_base_url=origin,
        default_ttl_seconds=pending_ttl_seconds,
    )
    federator = FakeASFederator()
    ps_signing = PSSigningService(signing_key_path)
    trust = MemoryAgentServerTrustRegistry(trust_file)
    if resource_jwks is None:
        resource_resolver: ResourceJWKSFetcher = ResourceJWKSResolver()
    else:
        resource_resolver = resource_jwks
    agent_resolver = AgentServerJWKSResolver(origin, trust, self_jwks_provider)
    auth_issuer = AuthTokenIssuer(
        origin,
        ps_signing,
        user_sub=user_id,
        auth_token_lifetime_seconds=auth_token_lifetime,
    )
    governance = PsGovernance(backend, store, ps_issuer=origin)
    lifecycle = MemoryMissionLifecycle(
        backend,
        store,
        ps_issuer=origin,
        auto_approve_mission=auto_approve_mission,
    )
    token_broker = MemoryTokenBroker(
        store,
        federator,
        backend,
        ps_origin=origin,
        auth_issuer=auth_issuer,
        resource_jwks=resource_resolver,
        agent_jwt_stub=agent_jwt_stub,
        auto_approve_without_consent=auto_approve_token,
        insecure_dev=insecure_dev,
    )
    consent = MemoryUserConsent(
        backend,
        store,
        federator,
        auth_issuer,
        agent_jwt_stub=agent_jwt_stub,
        ps_issuer=origin,
    )
    control = MemoryMissionControl(backend)
    return PSContainer(
        mission=backend,
        pending_store=store,
        federator=federator,
        lifecycle=lifecycle,
        token_broker=token_broker,
        user_consent=consent,
        mission_control=control,
        governance=governance,
        ps_signing=ps_signing,
        trust_registry=trust,
        agent_jwks_resolver=agent_resolver,
        resource_jwks_resolver=resource_resolver,
        auth_issuer=auth_issuer,
    )
