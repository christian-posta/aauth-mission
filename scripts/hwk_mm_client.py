#!/usr/bin/env python3
"""HWK-signed HTTP client for MM agent routes: POST /token, poll GET /pending/{id}.

Requires: aauth (project dependency), server with AAUTH_MM_INSECURE_DEV=false.

Example:
  AAUTH_MM_INSECURE_DEV=false uvicorn mm.http.app:app --host 127.0.0.1 --port 8000
  ./scripts/hwk-mm-client.sh --base-url http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import aauth
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _load_or_create_private_key(key_path: Path) -> Any:
    if key_path.exists():
        pem = key_path.read_bytes()
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise SystemExit(f"Key in {key_path} must be Ed25519 (HWK uses Ed25519).")
        return key
    pk, _pub = aauth.generate_ed25519_keypair()
    pem = pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(pem)
    try:
        key_path.chmod(0o600)
    except OSError:
        pass
    print(f"Generated new Ed25519 key (HWK): {key_path}", file=sys.stderr)
    return pk


def _sign_post(base: str, path: str, body: dict, private_key: Any) -> tuple[bytes, dict[str, str]]:
    body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")
    target = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
    parsed = urlparse(target)
    host = parsed.netloc
    if not host:
        raise SystemExit(f"Invalid base URL for signing: {base!r}")
    hdrs: dict[str, str] = {"Host": host, "Content-Type": "application/json"}
    signed = aauth.sign_request(
        "POST",
        target,
        hdrs,
        body_bytes,
        private_key=private_key,
        sig_scheme="hwk",
    )
    out = dict(signed)
    out["Content-Type"] = "application/json"
    return body_bytes, out


def _sign_get(base: str, full_path_or_url: str, private_key: Any) -> dict[str, str]:
    """full_path_or_url: absolute path like /pending/x or full URL."""
    if full_path_or_url.startswith("http://") or full_path_or_url.startswith("https://"):
        target = full_path_or_url
    else:
        target = urljoin(base.rstrip("/") + "/", full_path_or_url.lstrip("/"))
    parsed = urlparse(target)
    host = parsed.netloc
    if not host:
        raise SystemExit(f"Could not determine Host for URL {target!r}")
    hdrs: dict[str, str] = {"Host": host}
    return aauth.sign_request("GET", target, hdrs, None, private_key=private_key, sig_scheme="hwk")


def _http_request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None = None,
) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, hdrs, resp.read()
    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return e.code, hdrs, e.read()


def _parse_json(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        return None


def _decode_jwt_payload_unverified(token: str) -> dict[str, Any] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload_b64 = parts[1]
    pad = "=" * ((4 - len(payload_b64) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload_b64 + pad)
        return json.loads(raw.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _aauth_requirement_code(header_val: str | None) -> str | None:
    if not header_val:
        return None
    m = re.search(r'code="([^"]+)"', header_val)
    return m.group(1) if m else None


def _print_outcome(status: int, body: Any) -> None:
    if status == 200 and isinstance(body, dict) and "auth_token" in body:
        token = body["auth_token"]
        print("\n--- Success: auth token received ---")
        print(f"expires_in: {body.get('expires_in')}")
        claims = _decode_jwt_payload_unverified(token)
        if claims is not None:
            print("\nJWT payload (unverified decode):")
            print(json.dumps(claims, indent=2))
        else:
            print("\nToken is not a 3-segment JWT; raw auth_token:")
            print(token)
        return

    if status == 403 and isinstance(body, dict):
        err = body.get("error", "")
        if err in ("denied", "abandoned"):
            print("\n--- Declined ---")
            print(json.dumps(body, indent=2))
            return

    print(f"\n--- Unexpected HTTP {status} ---")
    print(json.dumps(body, indent=2) if body is not None else "(empty body)")


def main() -> None:
    default_key = Path(__file__).resolve().parent / ".hwk-mm-client-key.pem"
    p = argparse.ArgumentParser(description="MM HWK client: request token and poll with HTTP message signatures.")
    p.add_argument(
        "--base-url",
        default=os.environ.get("AAUTH_MM_BASE_URL", "http://127.0.0.1:8000"),
        help="MM base URL (no trailing path). Env: AAUTH_MM_BASE_URL",
    )
    p.add_argument(
        "--key-file",
        type=Path,
        default=default_key,
        help=f"PEM file for Ed25519 private key (created if missing). Default: {default_key}",
    )
    p.add_argument(
        "--resource-token",
        default="hwk-client-demo-resource-jwt",
        help="resource_token value for POST /token",
    )
    p.add_argument(
        "--poll-interval",
        type=float,
        default=1.0,
        help="Seconds between polls when status is 202",
    )
    p.add_argument(
        "--max-polls",
        type=int,
        default=600,
        help="Max poll attempts before giving up",
    )
    args = p.parse_args()

    base = args.base_url.rstrip("/")
    pk = _load_or_create_private_key(args.key_file)

    print("POST /token (HWK-signed)...", file=sys.stderr)
    body_bytes, hdrs = _sign_post(base, "/token", {"resource_token": args.resource_token}, pk)
    token_url = f"{base}/token"
    status, rh, raw = _http_request("POST", token_url, hdrs, body_bytes)
    data = _parse_json(raw)

    if status == 200:
        _print_outcome(status, data)
        return

    if status != 202:
        print(f"POST /token failed: HTTP {status}", file=sys.stderr)
        print(json.dumps(data, indent=2) if data else raw.decode("utf-8", errors="replace"))
        raise SystemExit(1)

    loc = rh.get("location") or (data or {}).get("pending_url")
    if not loc:
        print("No Location header for 202 response.", file=sys.stderr)
        raise SystemExit(1)

    pending_url = loc if loc.startswith("http") else urljoin(base + "/", loc.lstrip("/"))
    req_line = rh.get("aauth-requirement", "")
    code = _aauth_requirement_code(req_line)
    consent_ui = urljoin(base + "/", "ui/consent.html")
    print("\nDeferred consent required (202). Approve in the Mission Manager UI:", file=sys.stderr)
    if code:
        print(f"  {consent_ui}?code={code}", file=sys.stderr)
    print(f"Or: GET {base}/interaction?code=<code>  then POST .../decision", file=sys.stderr)
    print("Polling GET Location with HWK signatures...\n", file=sys.stderr)

    n = 0
    while n < args.max_polls:
        n += 1
        # Location may be /pending/... — sign with full URL the server uses
        poll_hdrs = _sign_get(base, pending_url, pk)
        st, ph, rawb = _http_request("GET", pending_url, poll_hdrs, None)
        pdata = _parse_json(rawb)

        if st == 200:
            _print_outcome(st, pdata)
            return
        if st == 403:
            _print_outcome(st, pdata)
            raise SystemExit(2)
        if st in (404, 408, 410, 429):
            print(f"Stopped polling: HTTP {st}", file=sys.stderr)
            print(json.dumps(pdata, indent=2) if pdata else rawb.decode("utf-8", errors="replace"))
            raise SystemExit(1)
        if st != 202:
            print(f"Unexpected HTTP {st} while polling", file=sys.stderr)
            print(json.dumps(pdata, indent=2) if pdata else rawb.decode("utf-8", errors="replace"))
            raise SystemExit(1)

        ra = ph.get("retry-after", "1")
        try:
            sleep_s = float(ra)
        except ValueError:
            sleep_s = float(args.poll_interval)
        time.sleep(max(sleep_s, args.poll_interval))

    print("Max polls exceeded; still pending.", file=sys.stderr)
    raise SystemExit(1)


if __name__ == "__main__":
    main()
