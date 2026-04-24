"""Mode-3 PS token endpoint: ``scheme=jwt`` + verified ``aa-resource+jwt``."""

from __future__ import annotations

import json
import time
from typing import Any

import aauth
import jwt
from jwt import PyJWKSet
import pytest
from fastapi.testclient import TestClient

from ps.federation.agent_server_trust import normalize_issuer
from ps.http.app import create_app
from ps.http.config import PSHttpSettings
from ps.impl import build_memory_ps


def _eddsa_jwk(priv, *, kid: str) -> dict[str, Any]:
    jwk = aauth.public_key_to_jwk(priv.public_key(), kid=kid)
    jwk["use"] = "sig"
    jwk["alg"] = "EdDSA"
    return jwk


def _jwks_from_priv(priv, *, kid: str) -> dict[str, Any]:
    return {"keys": [_eddsa_jwk(priv, kid=kid)]}


@pytest.fixture
def ps_origin() -> str:
    return "http://testserver"


@pytest.fixture
def resource_iss() -> str:
    return "https://rs.example"


@pytest.fixture
def key_material(
    resource_iss: str,
) -> tuple[
    str,
    Any,
    Any,
    Any,
    str,
    str,
    str,
    Any,
]:
    """Returns agent_id, ephemeral priv, AS priv, RS priv, AS kid, RS kid, resource_iss, fetcher."""
    agent_id = "mode3-test-agent"

    eph_priv, _eph_pub = aauth.generate_ed25519_keypair()
    eph_pub_jwk = _eddsa_jwk(eph_priv, kid="eph")
    agent_jkt = aauth.calculate_jwk_thumbprint(dict(eph_pub_jwk))

    as_priv, _ = aauth.generate_ed25519_keypair()
    as_kid = "as-kid"
    as_jwks = _jwks_from_priv(as_priv, kid=as_kid)

    rs_priv, _ = aauth.generate_ed25519_keypair()
    rs_kid = "rs-kid"

    def fetcher(iss: str) -> dict[str, Any] | None:
        if normalize_issuer(iss) == normalize_issuer(resource_iss):
            return _jwks_from_priv(rs_priv, kid=rs_kid)
        return None

    return agent_id, eph_priv, as_priv, rs_priv, as_kid, rs_kid, resource_iss, fetcher


def _mode3_app(
    *,
    ps_origin: str,
    auto_approve: bool,
    key_material: tuple,
    self_jwks: dict[str, Any],
) -> TestClient:
    _agent_id, _eph_priv, _as_priv, _rs_priv, _as_kid, _rs_kid, _resource_iss, fetcher = key_material

    self_provider = lambda: self_jwks

    ps = build_memory_ps(
        public_origin=ps_origin,
        auto_approve_token=auto_approve,
        insecure_dev=False,
        signing_key_path=None,
        trust_file=None,
        self_jwks_provider=self_provider,
        resource_jwks=fetcher,
    )
    settings = PSHttpSettings(
        public_origin=ps_origin,
        insecure_dev=False,
        auto_approve_token=auto_approve,
        signing_key_path=None,
        trust_file=None,
    )
    app = create_app(settings, ps_container=ps)
    return TestClient(app)


def _sign_token_request(
    resource_jwt: str,
    agent_jwt: str,
    eph_priv: Any,
) -> tuple[bytes, dict[str, str]]:
    body = {"resource_token": resource_jwt}
    body_bytes = json.dumps(body).encode("utf-8")
    target = "http://testserver/token"
    hdrs = aauth.sign_request(
        "POST",
        target,
        {"Host": "testserver", "Content-Type": "application/json"},
        body_bytes,
        private_key=eph_priv,
        sig_scheme="jwt",
        jwt=agent_jwt,
    )
    out = dict(hdrs)
    out["Content-Type"] = "application/json"
    return body_bytes, out


def test_mode3_post_token_issues_real_auth_jwt(
    ps_origin: str, resource_iss: str, key_material: tuple
) -> None:
    agent_id, eph_priv, as_priv, rs_priv, as_kid, rs_kid, _riss, _fetcher = key_material

    now = int(time.time())
    agent_jwt = aauth.create_agent_token(
        iss=ps_origin,
        sub=agent_id,
        cnf_jwk=_eddsa_jwk(eph_priv, kid="eph"),
        private_key=as_priv,
        kid=as_kid,
        exp=now + 3600,
    )
    eph_pub_jwk = _eddsa_jwk(eph_priv, kid="eph")
    agent_jkt = aauth.calculate_jwk_thumbprint(dict(eph_pub_jwk))

    resource_jwt = aauth.create_resource_token(
        iss=resource_iss,
        aud=ps_origin,
        agent=agent_id,
        agent_jkt=agent_jkt,
        scope="demo.scope",
        private_key=rs_priv,
        kid=rs_kid,
        exp=now + 3600,
    )

    c = _mode3_app(
        ps_origin=ps_origin,
        auto_approve=True,
        key_material=key_material,
        self_jwks=_jwks_from_priv(as_priv, kid=as_kid),
    )
    body_bytes, hdrs = _sign_token_request(resource_jwt, agent_jwt, eph_priv)
    r = c.post("/token", content=body_bytes, headers=hdrs)
    assert r.status_code == 200, r.text
    auth = r.json()["auth_token"]
    assert auth.startswith("eyJ")
    claims = jwt.decode(auth, options={"verify_signature": False})
    assert claims.get("iss") == ps_origin
    assert claims.get("aud") == resource_iss
    assert claims.get("agent") == agent_id
    assert claims.get("sub") == "user"
    assert claims.get("scope") == "demo.scope"
    assert claims.get("dwk") == "aauth-person.json"
    assert claims.get("act", {}).get("sub") == agent_id

    ps = c.app.state.ps
    jwks = PyJWKSet.from_dict(ps.ps_signing.get_jwks())
    kid = jwt.get_unverified_header(auth)["kid"]
    key = jwks[kid].key
    jwt.decode(auth, key, algorithms=["EdDSA"], audience=resource_iss)


def test_mode3_unknown_agent_issuer_returns_invalid_agent_token(
    ps_origin: str, key_material: tuple
) -> None:
    agent_id, eph_priv, as_priv, rs_priv, as_kid, rs_kid, resource_iss, _ = key_material
    now = int(time.time())
    agent_jwt = aauth.create_agent_token(
        iss="https://unknown-agent-issuer.example",
        sub=agent_id,
        cnf_jwk=_eddsa_jwk(eph_priv, kid="eph"),
        private_key=as_priv,
        kid=as_kid,
        exp=now + 3600,
    )
    eph_pub_jwk = _eddsa_jwk(eph_priv, kid="eph")
    agent_jkt = aauth.calculate_jwk_thumbprint(dict(eph_pub_jwk))
    resource_jwt = aauth.create_resource_token(
        iss=resource_iss,
        aud=ps_origin,
        agent=agent_id,
        agent_jkt=agent_jkt,
        scope="demo.scope",
        private_key=rs_priv,
        kid=rs_kid,
        exp=now + 3600,
    )
    c = _mode3_app(
        ps_origin=ps_origin,
        auto_approve=True,
        key_material=key_material,
        self_jwks=_jwks_from_priv(as_priv, kid=as_kid),
    )
    body_bytes, hdrs = _sign_token_request(resource_jwt, agent_jwt, eph_priv)
    r = c.post("/token", content=body_bytes, headers=hdrs)
    assert r.status_code == 401
    err = r.json()
    assert err.get("error") == "invalid_agent_token"


def test_mode3_tampered_resource_token(
    ps_origin: str, key_material: tuple
) -> None:
    agent_id, eph_priv, as_priv, rs_priv, as_kid, rs_kid, resource_iss, _ = key_material
    now = int(time.time())
    agent_jwt = aauth.create_agent_token(
        iss=ps_origin,
        sub=agent_id,
        cnf_jwk=_eddsa_jwk(eph_priv, kid="eph"),
        private_key=as_priv,
        kid=as_kid,
        exp=now + 3600,
    )
    eph_pub_jwk = _eddsa_jwk(eph_priv, kid="eph")
    agent_jkt = aauth.calculate_jwk_thumbprint(dict(eph_pub_jwk))
    resource_jwt = aauth.create_resource_token(
        iss=resource_iss,
        aud=ps_origin,
        agent=agent_id,
        agent_jkt=agent_jkt,
        scope="demo.scope",
        private_key=rs_priv,
        kid=rs_kid,
        exp=now + 3600,
    )
    resource_jwt = resource_jwt[:-4] + "xxxx"

    c = _mode3_app(
        ps_origin=ps_origin,
        auto_approve=True,
        key_material=key_material,
        self_jwks=_jwks_from_priv(as_priv, kid=as_kid),
    )
    body_bytes, hdrs = _sign_token_request(resource_jwt, agent_jwt, eph_priv)
    r = c.post("/token", content=body_bytes, headers=hdrs)
    assert r.status_code == 401
    assert r.json().get("error") == "invalid_resource_token"


def test_mode3_issues_without_consent_when_scope_omits_require_user(
    ps_origin: str, resource_iss: str, key_material: tuple
) -> None:
    """``AAUTH_PS_AUTO_APPROVE_TOKEN=false`` but scope has no ``require:user`` → immediate issuance."""
    agent_id, eph_priv, as_priv, rs_priv, as_kid, rs_kid, _riss, _ = key_material
    now = int(time.time())
    agent_jwt = aauth.create_agent_token(
        iss=ps_origin,
        sub=agent_id,
        cnf_jwk=_eddsa_jwk(eph_priv, kid="eph"),
        private_key=as_priv,
        kid=as_kid,
        exp=now + 3600,
    )
    eph_pub_jwk = _eddsa_jwk(eph_priv, kid="eph")
    agent_jkt = aauth.calculate_jwk_thumbprint(dict(eph_pub_jwk))
    resource_jwt = aauth.create_resource_token(
        iss=resource_iss,
        aud=ps_origin,
        agent=agent_id,
        agent_jkt=agent_jkt,
        scope="read:calendar",
        private_key=rs_priv,
        kid=rs_kid,
        exp=now + 3600,
    )
    c = _mode3_app(
        ps_origin=ps_origin,
        auto_approve=False,
        key_material=key_material,
        self_jwks=_jwks_from_priv(as_priv, kid=as_kid),
    )
    body_bytes, hdrs = _sign_token_request(resource_jwt, agent_jwt, eph_priv)
    r = c.post("/token", content=body_bytes, headers=hdrs)
    assert r.status_code == 200, r.text
    assert r.json()["auth_token"].startswith("eyJ")


def test_mode3_defers_for_consent_when_scope_includes_require_user(
    ps_origin: str, resource_iss: str, key_material: tuple
) -> None:
    agent_id, eph_priv, as_priv, rs_priv, as_kid, rs_kid, _riss, _ = key_material
    now = int(time.time())
    agent_jwt = aauth.create_agent_token(
        iss=ps_origin,
        sub=agent_id,
        cnf_jwk=_eddsa_jwk(eph_priv, kid="eph"),
        private_key=as_priv,
        kid=as_kid,
        exp=now + 3600,
    )
    eph_pub_jwk = _eddsa_jwk(eph_priv, kid="eph")
    agent_jkt = aauth.calculate_jwk_thumbprint(dict(eph_pub_jwk))
    resource_jwt = aauth.create_resource_token(
        iss=resource_iss,
        aud=ps_origin,
        agent=agent_id,
        agent_jkt=agent_jkt,
        scope="read:profile require:user",
        private_key=rs_priv,
        kid=rs_kid,
        exp=now + 3600,
    )
    c = _mode3_app(
        ps_origin=ps_origin,
        auto_approve=False,
        key_material=key_material,
        self_jwks=_jwks_from_priv(as_priv, kid=as_kid),
    )
    body_bytes, hdrs = _sign_token_request(resource_jwt, agent_jwt, eph_priv)
    r = c.post("/token", content=body_bytes, headers=hdrs)
    assert r.status_code == 202
    assert r.json().get("status") == "pending"


def test_four_party_aud_not_ps_still_fake_federator(
    ps_origin: str, key_material: tuple
) -> None:
    agent_id, eph_priv, as_priv, rs_priv, as_kid, rs_kid, resource_iss, _ = key_material
    now = int(time.time())
    agent_jwt = aauth.create_agent_token(
        iss=ps_origin,
        sub=agent_id,
        cnf_jwk=_eddsa_jwk(eph_priv, kid="eph"),
        private_key=as_priv,
        kid=as_kid,
        exp=now + 3600,
    )
    eph_pub_jwk = _eddsa_jwk(eph_priv, kid="eph")
    agent_jkt = aauth.calculate_jwk_thumbprint(dict(eph_pub_jwk))
    resource_jwt = aauth.create_resource_token(
        iss=resource_iss,
        aud="https://other-resource-party.example",
        agent=agent_id,
        agent_jkt=agent_jkt,
        scope="demo.scope",
        private_key=rs_priv,
        kid=rs_kid,
        exp=now + 3600,
    )
    c = _mode3_app(
        ps_origin=ps_origin,
        auto_approve=True,
        key_material=key_material,
        self_jwks=_jwks_from_priv(as_priv, kid=as_kid),
    )
    body_bytes, hdrs = _sign_token_request(resource_jwt, agent_jwt, eph_priv)
    r = c.post("/token", content=body_bytes, headers=hdrs)
    assert r.status_code == 200
    assert r.json()["auth_token"].startswith("aa-auth.fake.")
