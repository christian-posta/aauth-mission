#!/usr/bin/env python3
"""
End-to-end agent server client: real HTTP Message Signatures (aauth) for
register / pending poll / refresh (jkt-jwt). Requires AAUTH_AS_INSECURE_DEV=false.

Uses stdlib urllib only (no requests). Run from repo root with project venv:

  .venv/bin/python scripts/agent-server-signed-walkthrough.py

Environment:
  AGENT_BASE            — server origin (default: http://localhost:8800)
  PERSON_TOKEN          — bearer for /person/* (default: mytoken)
  PENDING_POLL_PREFIX   — registration poll path prefix (default: /pending). Use /register/pending
                          for the unified portal (portal.http.app); standalone agent_server uses /pending.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any

import aauth
import jwt as pyjwt


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def build_jkt_jwt(
    stable_priv: Any,
    stable_pub_jwk: dict[str, Any],
    new_eph_pub_jwk: dict[str, Any],
    ttl: int = 300,
) -> str:
    """Build jkt-s256+jwt delegating HTTP signing to new_eph_pub (cnf.jwk)."""
    stable_jkt = f"urn:jkt:sha-256:{aauth.calculate_jwk_thumbprint(stable_pub_jwk)}"
    now = int(time.time())
    header = {
        "alg": "EdDSA",
        "typ": "jkt-s256+jwt",
        "jwk": stable_pub_jwk,
    }
    payload = {
        "iss": stable_jkt,
        "iat": now,
        "exp": now + ttl,
        "cnf": {"jwk": new_eph_pub_jwk},
    }
    header_enc = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_enc = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_enc}.{payload_enc}".encode()
    sig = stable_priv.sign(signing_input)
    return f"{header_enc}.{payload_enc}.{_b64url(sig)}"


def _merge_sign_headers(
    method: str,
    target_uri: str,
    body: bytes | None,
    ephemeral_priv: Any,
    sig_scheme: str = "hwk",
    **kwargs: Any,
) -> dict[str, str]:
    headers: dict[str, str] = {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    sig = aauth.sign_request(
        method=method,
        target_uri=target_uri,
        headers=headers,
        body=body,
        private_key=ephemeral_priv,
        sig_scheme=sig_scheme,
        **kwargs,
    )
    return {**headers, **sig}


def http_do(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 — CLI tool
            rh = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, rh, resp.read()
    except urllib.error.HTTPError as e:
        rh = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return e.code, rh, e.read()


def _print_section(title: str) -> None:
    print(f"\n--- {title} ---")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base",
        default=os.environ.get("AGENT_BASE", "http://localhost:8800"),
        help="Agent server origin (or set AGENT_BASE)",
    )
    parser.add_argument(
        "--person-token",
        default=os.environ.get("PERSON_TOKEN", "mytoken"),
        help="Bearer token for /person/* (or set PERSON_TOKEN)",
    )
    parser.add_argument(
        "--skip-refresh",
        action="store_true",
        help="Stop after registration + first agent token (no POST /refresh)",
    )
    parser.add_argument(
        "--pending-prefix",
        default=os.environ.get("PENDING_POLL_PREFIX", "/pending"),
        help="Poll path after POST /register (default /pending; use /register/pending for portal)",
    )
    args = parser.parse_args()
    base = args.base.rstrip("/")
    person_token = args.person_token
    pending_prefix = args.pending_prefix.rstrip("/")
    if not pending_prefix.startswith("/"):
        pending_prefix = "/" + pending_prefix

    print("Generating Ed25519 key pairs (stable + ephemeral)…")
    stable_priv, stable_pub = aauth.generate_ed25519_keypair()
    eph_priv, _eph_pub = aauth.generate_ed25519_keypair()
    stable_pub_jwk = aauth.public_key_to_jwk(stable_pub)
    eph_pub_jwk = aauth.public_key_to_jwk(_eph_pub)
    stable_jkt = f"urn:jkt:sha-256:{aauth.calculate_jwk_thumbprint(stable_pub_jwk)}"
    print(f"Stable JKT: {stable_jkt}")

    _print_section("GET /.well-known/aauth-agent.json")
    wh_url = f"{base}/.well-known/aauth-agent.json"
    code, _h, raw = http_do("GET", wh_url, {}, None)
    if code != 200:
        print(f"ERROR: expected 200 from well-known, got {code}: {raw.decode()[:500]}", file=sys.stderr)
        return 1
    meta = json.loads(raw.decode())
    print(json.dumps(meta, indent=2))
    issuer = meta.get("issuer")
    if not issuer:
        print("ERROR: well-known missing issuer", file=sys.stderr)
        return 1

    _print_section("POST /register")
    reg_url = f"{base}/register"
    body_obj = {"stable_pub": stable_pub_jwk, "label": "Signed walkthrough client"}
    body_bytes = json.dumps(body_obj).encode()
    hdrs = _merge_sign_headers("POST", reg_url, body_bytes, eph_priv, sig_scheme="hwk")
    code, rh, raw = http_do("POST", reg_url, hdrs, body_bytes)
    if code != 202:
        print(
            f"ERROR: expected 202 from POST /register, got {code}: {raw.decode()[:800]}",
            file=sys.stderr,
        )
        return 1
    loc = rh.get("location", "")
    print(f"HTTP {code}  Location: {loc}")
    reg_json = json.loads(raw.decode())
    print(json.dumps(reg_json, indent=2))
    if reg_json.get("status") != "pending":
        print("ERROR: expected body status pending", file=sys.stderr)
        return 1
    pending_id = loc.rstrip("/").split("/")[-1]
    print(f"Pending ID: {pending_id}")

    _print_section(f"GET {pending_prefix}/{{id}} (before approval)")
    pend_url = f"{base}{pending_prefix}/{pending_id}"
    hdrs = _merge_sign_headers("GET", pend_url, None, eph_priv)
    code, _rh, raw = http_do("GET", pend_url, hdrs, None)
    print(f"HTTP {code}  {raw.decode()}")
    if code != 202:
        print("ERROR: expected 202 before approval", file=sys.stderr)
        return 1

    _print_section("POST /person/registrations/{id}/approve")
    appr_url = f"{base}/person/registrations/{pending_id}/approve"
    code, _rh, raw = http_do(
        "POST",
        appr_url,
        {"Authorization": f"Bearer {person_token}"},
        None,
    )
    if code != 200:
        print(f"ERROR: approve failed HTTP {code}: {raw.decode()[:800]}", file=sys.stderr)
        return 1
    appr = json.loads(raw.decode())
    print(json.dumps(appr, indent=2))
    agent_id = appr["agent_id"]

    _print_section(f"GET {pending_prefix}/{{id}} (after approval)")
    hdrs = _merge_sign_headers("GET", pend_url, None, eph_priv)
    code, _rh, raw = http_do("GET", pend_url, hdrs, None)
    if code != 200:
        print(f"ERROR: expected 200 after approval, got {code}: {raw.decode()[:800]}", file=sys.stderr)
        return 1
    pend_after = json.loads(raw.decode())
    agent_token = pend_after["agent_token"]
    print(f"HTTP {code}  agent_token: {agent_token[:50]}…")

    payload = pyjwt.decode(agent_token, options={"verify_signature": False})
    if payload.get("iss") != issuer:
        print(f"ERROR: token iss {payload.get('iss')!r} != well-known issuer {issuer!r}", file=sys.stderr)
        return 1
    if payload.get("sub") != agent_id:
        print("ERROR: token sub != agent_id", file=sys.stderr)
        return 1
    if payload.get("dwk") != "aauth-agent.json":
        print("ERROR: token dwk", file=sys.stderr)
        return 1
    cnf = payload.get("cnf") or {}
    if cnf.get("jwk", {}).get("x") != eph_pub_jwk["x"]:
        print("ERROR: cnf.jwk.x != registration ephemeral key", file=sys.stderr)
        return 1
    print("Token claims (decoded, signature not verified):")
    print(json.dumps(payload, indent=2))

    print("\n=== Registration + signed requests complete ===")
    print(f"Agent ID: {agent_id}")
    print(f"Token exp: {payload['exp']} ({payload['exp'] - int(time.time())}s from now)")

    if args.skip_refresh:
        print("\n(--skip-refresh: not calling POST /refresh)")
        return 0

    _print_section("POST /refresh (jkt-jwt)")
    new_eph_priv, new_eph_pub = aauth.generate_ed25519_keypair()
    new_eph_pub_jwk = aauth.public_key_to_jwk(new_eph_pub)
    jkt_jwt = build_jkt_jwt(stable_priv, stable_pub_jwk, new_eph_pub_jwk)
    refresh_url = f"{base}/refresh"
    hdrs = _merge_sign_headers(
        "POST",
        refresh_url,
        None,
        new_eph_priv,
        sig_scheme="jkt-jwt",
        jwt=jkt_jwt,
    )
    code, _rh, raw = http_do("POST", refresh_url, hdrs, None)
    if code != 200:
        print(f"ERROR: refresh expected 200, got {code}: {raw.decode()[:800]}", file=sys.stderr)
        return 1
    new_token = json.loads(raw.decode())["agent_token"]
    new_payload = pyjwt.decode(new_token, options={"verify_signature": False})
    if new_payload.get("sub") != agent_id:
        print("ERROR: after refresh sub changed", file=sys.stderr)
        return 1
    if new_payload.get("cnf", {}).get("jwk", {}).get("x") != new_eph_pub_jwk["x"]:
        print("ERROR: after refresh cnf.jwk.x mismatch", file=sys.stderr)
        return 1
    print(f"HTTP {code}  new agent_token: {new_token[:50]}…")
    print("New token cnf.jwk.x matches new ephemeral key.")
    print("\n=== Refresh (jkt-jwt) complete ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
