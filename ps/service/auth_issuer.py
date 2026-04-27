"""Issue PS-signed ``aa-auth+jwt`` (SPEC §Auth Token, three-party)."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

import aauth

from ps.models import AuthTokenResponse, MissionRef
from ps.service.issued_token_store import IssuedTokenStore
from ps.service.signing import PSSigningService


class AuthTokenIssuer:
    def __init__(
        self,
        ps_origin: str,
        signing: PSSigningService,
        *,
        user_sub: str,
        auth_token_lifetime_seconds: int = 3600,
        issued_token_store: IssuedTokenStore | None = None,
    ) -> None:
        self._iss = ps_origin.rstrip("/")
        self._signing = signing
        self._user_sub = user_sub
        lt = min(auth_token_lifetime_seconds, 3600)
        self._lifetime = max(60, lt)
        self._store = issued_token_store

    def issue(
        self,
        *,
        agent_id: str,
        agent_cnf_jwk: dict[str, Any],
        resource_claims: dict[str, Any],
        mission: MissionRef | None,
        justification: str | None = None,
        issue_method: str = "autonomous",
    ) -> AuthTokenResponse:
        resource_iss = str(resource_claims["iss"])
        scope = str(resource_claims.get("scope", ""))
        mission_obj: dict[str, Any] | None = None
        if mission is not None:
            mission_obj = {"approver": mission.approver, "s256": mission.s256}
        elif resource_claims.get("mission") is not None:
            m = resource_claims["mission"]
            if isinstance(m, dict):
                mission_obj = dict(m)

        exp = int(time.time()) + self._lifetime
        token = aauth.create_auth_token(
            iss=self._iss,
            aud=resource_iss,
            agent=agent_id,
            cnf_jwk=agent_cnf_jwk,
            private_key=self._signing.private_key,
            kid=self._signing.kid,
            act={"sub": agent_id},
            scope=scope,
            sub=self._user_sub,
            exp=exp,
            mission=mission_obj,
            dwk="aauth-person.json",
        )

        if self._store is not None:
            expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
            try:
                self._store.record_issued(
                    auth_token=token,
                    agent_id=agent_id,
                    owner_id=self._user_sub,
                    resource_iss=resource_iss,
                    resource_scope=scope or None,
                    justification=justification,
                    issue_method=issue_method,
                    expires_at=expires_at,
                )
            except Exception:
                pass  # never block token issuance due to audit failure

        return AuthTokenResponse(auth_token=token, expires_in=self._lifetime)
