#!/usr/bin/env python3
"""Drive Person Server **mode 3** ``POST /token`` (``scheme=jwt`` + real ``aa-resource+jwt``).

Prerequisites (example unified portal):

- ``AAUTH_PS_INSECURE_DEV=false`` — ``/token`` requires ``Signature-Key: ... scheme=jwt`` with an
  ``aa-agent+jwt`` and a matching HTTP message signature.
- ``AAUTH_PS_AUTO_APPROVE_TOKEN=true`` — optional; skips all consent. If ``false``, this script still gets an
  immediate token because it mints a resource JWT with scope ``demo`` (no ``require:user``).
- ``AAUTH_AS_INSECURE_DEV=true`` — so this script can ``POST /register`` with stub HWK signatures
  (production agents should use real signing per CLIENTS.md).

The script starts a tiny HTTP server on localhost that serves ``/.well-known/aauth-resource.json``
and JWKS so the Person Server can verify a synthetic resource token.

Usage::

    .venv/bin/python scripts/ps-token-mode3.py --base http://127.0.0.1:8765

See also: CLIENTS.md (Person Server as authorization server), TRUST.md (agent-server trust).
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

import aauth
import jwt


def _http_json(
    method: str,
    url: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
):
    h = dict(headers or {})
    if body is not None:
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
            ctype = resp.headers.get("Content-Type", "")
            if "application/json" in ctype and raw:
                return resp.status, dict(resp.headers), json.loads(raw)
            return resp.status, dict(resp.headers), raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            payload = {"detail": raw}
        return e.code, dict(e.headers), payload


def _eddsa_jwk(priv: Any, *, kid: str) -> dict[str, Any]:
    jwk = aauth.public_key_to_jwk(priv.public_key(), kid=kid)
    jwk["use"] = "sig"
    jwk["alg"] = "EdDSA"
    return jwk


def _jwks(priv: Any, *, kid: str) -> dict[str, Any]:
    return {"keys": [_eddsa_jwk(priv, kid=kid)]}


class _ResourceMetaHandler(BaseHTTPRequestHandler):
    jwks_json: str
    issuer: str

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/.well-known/aauth-resource.json"):
            body = json.dumps(
                {
                    "issuer": self.issuer,
                    "jwks_uri": f"{self.issuer}/.well-known/jwks.json",
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/.well-known/jwks.json"):
            raw = self.jwks_json.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        self.send_error(404)


def main() -> int:
    ap = argparse.ArgumentParser(description="PS mode-3 token demo (scheme=jwt + resource JWT).")
    ap.add_argument("--base", default="http://127.0.0.1:8765", help="Portal or PS base URL")
    args = ap.parse_args()
    base = args.base.rstrip("/")

    st, _, person = _http_json("GET", f"{base}/.well-known/aauth-person.json", body=None)
    if st != 200 or not isinstance(person, dict):
        print("Failed to load aauth-person.json", file=sys.stderr)
        return 1
    ps_issuer = str(person["issuer"])

    st, _, agent_meta = _http_json("GET", f"{base}/.well-known/aauth-agent.json", body=None)
    if st != 200 or not isinstance(agent_meta, dict):
        print("Failed to load aauth-agent.json", file=sys.stderr)
        return 1
    reg_ep = str(agent_meta.get("registration_endpoint", f"{base}/register"))

    stable_priv, _stable_pub = aauth.generate_ed25519_keypair()
    stable_jwk = _eddsa_jwk(stable_priv, kid="stable")
    eph_priv, _eph_pub = aauth.generate_ed25519_keypair()

    reg_body = {"stable_pub": stable_jwk, "agent_name": "ps-token-mode3 demo"}
    target = reg_ep if reg_ep.startswith("http") else f"{base}{reg_ep}"
    body_bytes = json.dumps(reg_body).encode("utf-8")
    hdrs = aauth.sign_request(
        "POST",
        target,
        {"Host": urlparse(target).netloc, "Content-Type": "application/json"},
        body_bytes,
        private_key=eph_priv,
        sig_scheme="hwk",
    )
    merged = {**hdrs, "Content-Type": "application/json"}

    st, headers, reg_out = _http_json("POST", target, body=body_bytes, headers=merged)
    agent_token: str | None = None
    if st == 200 and isinstance(reg_out, dict):
        agent_token = reg_out.get("agent_token")
    elif st == 202:
        loc = headers.get("Location") or headers.get("location")
        if not loc:
            print("202 from register but no Location", file=sys.stderr)
            return 1
        poll_url = loc if loc.startswith("http") else f"{base}{loc}"
        ra = int(headers.get("Retry-After", "1") or "1")
        for _ in range(120):
            time.sleep(max(1, ra))
            poll_bytes = b""
            ph = aauth.sign_request(
                "GET",
                poll_url,
                {"Host": urlparse(poll_url).netloc},
                poll_bytes,
                private_key=eph_priv,
                sig_scheme="hwk",
            )
            st2, _, poll_out = _http_json("GET", poll_url, body=None, headers=ph)
            if st2 == 200 and isinstance(poll_out, dict) and poll_out.get("agent_token"):
                agent_token = poll_out["agent_token"]
                break
            if st2 not in (200, 202):
                print("Poll failed:", st2, poll_out, file=sys.stderr)
                return 1
    else:
        print("Register failed:", st, reg_out, file=sys.stderr)
        return 1

    if not agent_token:
        print("No agent_token from registration", file=sys.stderr)
        return 1

    rs_priv, _ = aauth.generate_ed25519_keypair()
    rs_kid = "mode3-rs"
    jwks_doc = json.dumps(_jwks(rs_priv, kid=rs_kid))

    server = ThreadingHTTPServer(("127.0.0.1", 0), _ResourceMetaHandler)
    _port = server.server_address[1]
    rs_issuer = f"http://127.0.0.1:{_port}"
    _ResourceMetaHandler.jwks_json = jwks_doc
    _ResourceMetaHandler.issuer = rs_issuer
    threading.Thread(target=server.serve_forever, daemon=True).start()

    claims = jwt.decode(agent_token, options={"verify_signature": False})
    agent_id = str(claims.get("sub", ""))
    cnf = (claims.get("cnf") or {}).get("jwk")
    if not agent_id or not cnf:
        print("Malformed agent token", file=sys.stderr)
        return 1
    agent_jkt = aauth.calculate_jwk_thumbprint(dict(cnf))

    now = int(time.time())
    resource_token = aauth.create_resource_token(
        iss=rs_issuer,
        aud=ps_issuer,
        agent=agent_id,
        agent_jkt=agent_jkt,
        scope="demo",
        private_key=rs_priv,
        kid=rs_kid,
        exp=now + 600,
    )

    tok_url = f"{base}/token"
    tok_body = json.dumps({"resource_token": resource_token}).encode("utf-8")
    tok_hdrs = aauth.sign_request(
        "POST",
        tok_url,
        {"Host": urlparse(tok_url).netloc, "Content-Type": "application/json"},
        tok_body,
        private_key=eph_priv,
        sig_scheme="jwt",
        jwt=agent_token,
    )
    tok_merged = {**tok_hdrs, "Content-Type": "application/json"}
    st3, _, tok_out = _http_json("POST", tok_url, body=tok_body, headers=tok_merged)
    if st3 != 200:
        print("POST /token failed:", st3, tok_out, file=sys.stderr)
        server.shutdown()
        return 1

    print(json.dumps(tok_out, indent=2))
    if isinstance(tok_out, dict) and tok_out.get("auth_token", "").startswith("eyJ"):
        auth_claims = jwt.decode(str(tok_out["auth_token"]), options={"verify_signature": False})
        print("\nDecoded auth token (unverified):\n", json.dumps(auth_claims, indent=2))
    server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
