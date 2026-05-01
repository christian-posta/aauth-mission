"""Assemble ``PSContainer`` and ``ASContainer`` with SQL stores."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sqlalchemy.orm import Session

from agent_server.impl import ASContainer
from agent_server.service.signing import SigningService
from agent_server.service.token_factory import AgentTokenFactory
from agent_server.impl.memory_replay import ReplayCache
from persistence.as_stores import SQLBindingStore, SQLPendingRegistrationStore
from persistence.engine import make_engine, create_session_factory
from persistence.sql_issued import DatabaseIssuedTokenStore
from persistence.sql_mission import SqlMissionState
from persistence.sql_pending import DatabasePendingStore
from persistence.trust_db import DatabaseAgentServerTrustRegistry, import_trust_from_file_if_empty
from ps.federation.agent_jwks import AgentServerJWKSResolver
from ps.federation.as_federator import ASFederator
from ps.federation.resource_jwks import ResourceJWKSFetcher, ResourceJWKSResolver
from ps.impl import PSContainer
from ps.impl.fake_federator import FakeASFederator
from ps.impl.memory_consent import MemoryUserConsent
from ps.impl.memory_control import MemoryMissionControl
from ps.impl.memory_lifecycle import MemoryMissionLifecycle
from ps.impl.memory_token import MemoryTokenBroker
from ps.impl.ps_governance import PsGovernance
from ps.service.auth_issuer import AuthTokenIssuer
from ps.service.consent_scopes import ConsentScopeStore
from ps.service.signing import PSSigningService

from persistence.base import Base


def init_db(engine: Any) -> None:
    """Create all tables (dev/tests). For production, prefer ``alembic upgrade head``."""
    Base.metadata.create_all(engine)


def build_persisted_ps(
    session_factory: Callable[[], Session],
    *,
    public_origin: str,
    auto_approve_token: bool = False,
    auto_approve_mission: bool = True,
    agent_jwt_stub: str = "stub-agent-jwt",
    pending_ttl_seconds: int = 600,
    signing_key_path: str | None = ".aauth/ps-signing-key.pem",
    trust_file: str | None = ".aauth/ps-trusted-agents.json",
    consent_scopes_file: str | None = ".aauth/consent-scopes.json",
    auth_token_lifetime: int = 3600,
    user_id: str = "user",
    insecure_dev: bool = False,
    self_jwks_provider: Any = None,
    resource_jwks: ResourceJWKSFetcher | None = None,
) -> PSContainer:
    import_trust_from_file_if_empty(session_factory, trust_file)
    origin = public_origin.rstrip("/")
    mission = SqlMissionState(session_factory)
    store = DatabasePendingStore(
        session_factory,
        mission,
        origin,
        default_ttl_seconds=pending_ttl_seconds,
    )
    federator: ASFederator = FakeASFederator()
    ps_signing = PSSigningService(signing_key_path)
    trust = DatabaseAgentServerTrustRegistry(session_factory)
    consent_scopes = ConsentScopeStore(consent_scopes_file)
    if resource_jwks is None:
        resource_resolver: ResourceJWKSFetcher = ResourceJWKSResolver()
    else:
        resource_resolver = resource_jwks
    agent_resolver = AgentServerJWKSResolver(origin, trust, self_jwks_provider)
    issued_store = DatabaseIssuedTokenStore(session_factory)
    auth_issuer = AuthTokenIssuer(
        origin,
        ps_signing,
        user_sub=user_id,
        auth_token_lifetime_seconds=auth_token_lifetime,
        issued_token_store=issued_store,
    )
    governance = PsGovernance(mission, store, ps_issuer=origin)  # type: ignore[arg-type]
    lifecycle = MemoryMissionLifecycle(
        mission,
        store,  # type: ignore[arg-type]
        ps_issuer=origin,
        auto_approve_mission=auto_approve_mission,
    )
    token_broker = MemoryTokenBroker(
        store,  # type: ignore[arg-type]
        federator,
        mission,
        ps_origin=origin,
        auth_issuer=auth_issuer,
        resource_jwks=resource_resolver,
        consent_scopes=consent_scopes,
        agent_jwt_stub=agent_jwt_stub,
        auto_approve_without_consent=auto_approve_token,
        insecure_dev=insecure_dev,
    )
    consent = MemoryUserConsent(
        mission,
        store,  # type: ignore[arg-type]
        federator,
        auth_issuer,
        agent_jwt_stub=agent_jwt_stub,
        ps_issuer=origin,
        resource_jwks=resource_resolver,
    )
    control = MemoryMissionControl(mission)
    return PSContainer(
        mission=mission,  # type: ignore[arg-type]
        pending_store=store,  # type: ignore[assignment]
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
        issued_token_store=issued_store,
        consent_scopes=consent_scopes,
    )


def build_persisted_as(
    session_factory: Callable[[], Session],
    *,
    issuer: str,
    server_domain: str,
    signing_key_path: str | None,
    previous_key_path: str | None,
    agent_token_lifetime: int,
    registration_ttl: int,
    signature_window: int,
    ps_url: str | None = None,
) -> ASContainer:
    signing = SigningService(
        issuer=issuer,
        server_domain=server_domain,
        signing_key_path=signing_key_path,
        previous_key_path=previous_key_path,
        agent_token_lifetime=agent_token_lifetime,
        ps_url=ps_url,
    )
    token_factory = AgentTokenFactory(signing=signing)
    registrations = SQLPendingRegistrationStore(session_factory, default_ttl=registration_ttl)
    bindings = SQLBindingStore(session_factory)
    replay = ReplayCache(window_seconds=signature_window)
    return ASContainer(
        registrations=registrations,  # type: ignore[assignment]
        bindings=bindings,  # type: ignore[assignment]
        replay=replay,
        signing=signing,
        token_factory=token_factory,
    )


def build_engine_and_session_from_url(url: str) -> tuple[Any, Callable[[], Session]]:
    eng = make_engine(url)
    return eng, create_session_factory(eng)
