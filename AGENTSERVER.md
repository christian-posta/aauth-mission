# AAuth Agent Server — Manual Testing Guide

This guide walks through every flow the agent server supports: enrollment, approval, polling, token renewal, multi-device linking, and revocation. It covers both the **UI** and **command-line / Python** approaches.

---

## Contents

1. [What the Agent Server Does](#1-what-the-agent-server-does)
2. [Start the Server](#2-start-the-server)
3. [Environment Variables](#3-environment-variables)
4. [UI Walkthrough](#4-ui-walkthrough)
5. [Testing with curl (insecure_dev mode)](#5-testing-with-curl-insecure_dev-mode)
6. [Testing with real HTTP signatures (Python)](#6-testing-with-real-http-signatures-python)
7. [Token Renewal (refresh / jkt-jwt)](#7-token-renewal-refresh--jkt-jwt)
8. [Multi-device: Linking a Second Device](#8-multi-device-linking-a-second-device)
9. [Revocation](#9-revocation)
10. [Verifying an Issued Agent Token](#10-verifying-an-issued-agent-token)
11. [API Reference](#11-api-reference)
12. [Troubleshooting](#12-troubleshooting)

> **Tested against:** `aauth==0.3.2`, Python 3.12, `uvicorn 0.27+`. All flows in this guide have been verified to work end-to-end.

---

## 1. What the Agent Server Does

The agent server implements **Path B: Direct Registration + Stable Key Renewal** from the AAuth protocol. There is no Person Server (PS) involved.

**Concept:**

```
Agent laptop                   Agent Server               Person (you)
     |                               |                         |
     | --- POST /register ---------> |                         |
     |   (stable_pub + eph_pub)      |                         |
     |                               | -- notify (via UI) ---> |
     |                               |                         |
     | --- GET /pending/{id} ------> |   (polling)             |
     |                               | <-- POST /approve ----- |
     |                               |                         |
     | <-- 200 agent_token --------- |                         |
     |                               |                         |
     |  ...24 hours later...         |                         |
     |                               |                         |
     | --- POST /refresh ----------> |   (no person needed)    |
     | <-- 200 new agent_token ----- |                         |
```

**Key concepts:**

- **Stable key**: An Ed25519 key stored in the OS Keychain. Lives forever. Proves the device's persistent identity.
- **Ephemeral key**: A short-lived Ed25519 key (≤24h). Used to sign HTTP requests and embedded in the agent token's `cnf.jwk`.
- **Binding**: The server's record mapping a stable key thumbprint (`urn:jkt:sha-256:...`) → `agent_id` (`aauth:<uuid>@<domain>`).
- **Agent token** (`aa-agent+jwt`): A JWT signed by the agent server. Contains `iss`, `sub` (agent_id), `cnf.jwk` (ephemeral pub), `dwk`, `jti`, `iat`, `exp`.

---

## 2. Start the Server

There are two ways to run the Agent Server: as a **unified portal** (combined with the Person Server, recommended for end-to-end testing) or as a **standalone** service.

### Unified portal (recommended — one process, one port)

Combines the Agent Server and Person Server into a single FastAPI app. See `README.md §Unified Person Portal` for full details.

```bash
cd /path/to/aauth-person-server
uv pip install -e ".[dev]"   # first time only

export AAUTH_PS_PUBLIC_ORIGIN=http://localhost:8765
export AAUTH_AS_PUBLIC_ORIGIN=http://localhost:8765
export AAUTH_PS_ADMIN_TOKEN=mytoken
export AAUTH_PS_INSECURE_DEV=true
export AAUTH_AS_PERSON_TOKEN=mytoken
export AAUTH_AS_INSECURE_DEV=true   # omit for production signatures

.venv/bin/uvicorn portal.http.app:app --reload --port 8765
```

> **Note:** In portal mode the `AAUTH_AS_ISSUER` and `AAUTH_AS_PUBLIC_ORIGIN` env vars are **overridden** by the portal to equal `AAUTH_PS_PUBLIC_ORIGIN`. Both well-known docs will advertise `issuer = http://localhost:8765`. The standalone AS env vars still apply when running the Agent Server by itself.

> **Registration poll path change:** in the portal the pending poll endpoint is `GET /register/pending/{id}` (not `/pending/{id}`, which the Person Server uses for token flows). See [§5](#5-testing-with-curl-insecure_dev-mode) and [§6](#6-testing-with-real-http-signatures-python) for how to run the walkthrough scripts against the portal.

Verify the portal is up:

```bash
curl -s http://localhost:8765/.well-known/aauth-agent.json | jq .
```

Expected (portal overrides `issuer` and `client_name`):
```json
{
  "issuer": "http://localhost:8765",
  "jwks_uri": "http://localhost:8765/.well-known/jwks.json",
  "client_name": "AAuth Person Portal",
  "registration_endpoint": "http://localhost:8765/register",
  "refresh_endpoint": "http://localhost:8765/refresh"
}
```

### Standalone Agent Server (insecure_dev mode)

Use when you want to run the Agent Server independently of the Person Server.

```bash
cd /path/to/aauth-person-server
uv pip install -e ".[dev]"

AAUTH_AS_PUBLIC_ORIGIN=http://localhost:8800 \
AAUTH_AS_ISSUER=http://localhost:8800 \
AAUTH_AS_SERVER_DOMAIN=localhost \
AAUTH_AS_PERSON_TOKEN=mytoken \
AAUTH_AS_INSECURE_DEV=true \
.venv/bin/uvicorn agent_server.http.app:app --reload --port 8800
```

### Standalone Agent Server (production signatures)

```bash
AAUTH_AS_PUBLIC_ORIGIN=https://agent-server.example \
AAUTH_AS_ISSUER=https://agent-server.example \
AAUTH_AS_SERVER_DOMAIN=agent-server.example \
AAUTH_AS_PERSON_TOKEN=mytoken \
AAUTH_AS_SIGNING_KEY_PATH=./keys/signing.pem \
.venv/bin/uvicorn agent_server.http.app:app --port 8800
```

On first run with `SIGNING_KEY_PATH` set, the server auto-generates and saves an Ed25519 key. On restart it loads the existing key, so issued tokens remain verifiable.

### Verify standalone AS is up

```bash
curl -s http://localhost:8800/.well-known/aauth-agent.json | jq .
```

Expected:
```json
{
  "issuer": "http://localhost:8800",
  "jwks_uri": "http://localhost:8800/.well-known/jwks.json",
  "client_name": "AAuth Agent Server",
  "registration_endpoint": "http://localhost:8800/register",
  "refresh_endpoint": "http://localhost:8800/refresh"
}
```

```bash
curl -s http://localhost:8800/.well-known/jwks.json | jq .
```

Expected:
```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "as-202604-xxxxxxxx",
      "x": "...",
      "use": "sig",
      "alg": "EdDSA"
    }
  ]
}
```

---

## 3. Environment Variables

All variables use the `AAUTH_AS_` prefix.

| Variable | Default | Description |
|----------|---------|-------------|
| `AAUTH_AS_PUBLIC_ORIGIN` | `http://localhost:8800` | Base URL in metadata. Must match browser origin for UI links to work. **Overridden by the portal** to equal `AAUTH_PS_PUBLIC_ORIGIN`. |
| `AAUTH_AS_ISSUER` | `https://agent-server.example` | `iss` claim in issued agent tokens. **Overridden by the portal** to equal `AAUTH_PS_PUBLIC_ORIGIN`. |
| `AAUTH_AS_SERVER_DOMAIN` | `agent-server.example` | Domain part of generated `aauth:<uuid>@<domain>` agent IDs. |
| `AAUTH_AS_PERSON_TOKEN` | `changeme` | Bearer token for all `/person/*` endpoints. **Change this.** In the portal, `AAUTH_PS_ADMIN_TOKEN` is also accepted on `/person/*`. |
| `AAUTH_AS_INSECURE_DEV` | `false` | Skip HTTP signature verification. Safe only for local development. |
| `AAUTH_AS_SIGNING_KEY_PATH` | *(unset)* | Path to Ed25519 PEM. Auto-generated if unset (ephemeral — tokens won't survive restarts). |
| `AAUTH_AS_PREVIOUS_KEY_PATH` | *(unset)* | Previous signing key PEM, kept in JWKS during rotation transition. |
| `AAUTH_AS_AGENT_TOKEN_LIFETIME` | `86400` | Token lifetime in seconds (max 86400 = 24h). |
| `AAUTH_AS_REGISTRATION_TTL` | `3600` | How long a pending registration stays open before auto-expiry (seconds). |
| `AAUTH_AS_SIGNATURE_WINDOW` | `60` | Allowed clock skew for HTTP signature `created` timestamp (seconds). |
| `AAUTH_AS_CLIENT_NAME` | `AAuth Agent Server` | Human-readable name in well-known metadata. Set to `"AAuth Person Portal"` by the portal. |

**Startup warning:** If `AAUTH_AS_PERSON_TOKEN=changeme` and `INSECURE_DEV=false`, the server logs a warning on startup. Change the token before exposing it on a network.

---

## 4. UI Walkthrough

### Portal UI (recommended)

When running the unified portal, open **`http://localhost:8765/ui/index.html`** in your browser. The portal dashboard combines agent management (Agents tab: pending registrations, active bindings) with mission and token-request management in a single 3-tab page. Sign in with the value of `AAUTH_PS_ADMIN_TOKEN` / `AAUTH_AS_PERSON_TOKEN`.

```bash
curl -so /dev/null -w "%{http_code}" http://localhost:8765/ui/index.html   # 200
curl -so /dev/null -w "%{http_code}" http://localhost:8765/ui/portal.html  # 200
curl -so /dev/null -w "%{http_code}" http://localhost:8765/ui/consent.html # 200
```

### Standalone Agent Server UI

The standalone agent server ships its own management UI at `/ui/`. All pages are static HTML + Alpine.js.

```bash
curl -si http://localhost:8800/ui/ | head -2
# Expected: HTTP/1.1 200 OK
```

All three pages must return 200:
```bash
curl -so /dev/null -w "%{http_code}" http://localhost:8800/ui/index.html         # 200
curl -so /dev/null -w "%{http_code}" http://localhost:8800/ui/registrations.html  # 200
curl -so /dev/null -w "%{http_code}" http://localhost:8800/ui/agents.html         # 200
```

### Sign in (`index.html`) — standalone AS

Open `http://localhost:8800/ui/` in your browser.

Enter the value of `AAUTH_AS_PERSON_TOKEN` (e.g. `mytoken`) and click **Sign in**.

What happens internally:
1. The form sends `GET /person/registrations` with `Authorization: Bearer <token>`
2. If the server returns 200, the session is stored in `sessionStorage` and the browser redirects to `registrations.html`
3. On 401/403, an error message is shown inline

You can verify authentication works from curl:
```bash
# Good token → 200
curl -si http://localhost:8800/person/registrations \
  -H "Authorization: Bearer mytoken" | head -1
# HTTP/1.1 200 OK

# Wrong token → 403
curl -si http://localhost:8800/person/registrations \
  -H "Authorization: Bearer badtoken" | head -1
# HTTP/1.1 403 Forbidden

# Missing auth → 401
curl -si http://localhost:8800/person/registrations | head -1
# HTTP/1.1 401 Unauthorized
```

### Pending Registrations (`registrations.html`)

This is the main approval page. When an agent calls `POST /register`, its request appears here within seconds (the page auto-refreshes every 5 seconds while items are pending).

Each card shows:
- **Label** — what the agent called itself (e.g. "MacBook Pro - Claude Agent")
- **Time since request** and **expiry countdown** (turns amber when <5 minutes remain)
- **Stable key JKT** — click to copy the full `urn:jkt:sha-256:...` identifier

**Actions per registration:**
- **Approve** — creates a new binding and a new `agent_id`. One click, no confirmation. Card disappears on success.
- **Deny** — with a confirmation dialog. The agent gets a 403 on its next poll. Card disappears on success.
- **Link to existing agent** — opens a modal listing your active bindings. Select one to add this device's stable key to it, so it shares the same `agent_id` as an existing device.

You can test the underlying API while the UI is open:
```bash
# Create a pending registration (requires running server with insecure_dev=true)
# See section 5 for full curl flow

# Manually trigger a refresh of the page:
curl -s http://localhost:8800/person/registrations \
  -H "Authorization: Bearer mytoken" | python3 -m json.tool
```

### My Agents (`agents.html`)

Shows all approved agent bindings split into **Active** and **Revoked** sections.

Each active binding card shows:
- **Label** and **agent_id** (click to copy the full `aauth:<uuid>@<domain>` identifier)
- **Device count** (how many stable keys enrolled)
- **Enrolled** — relative time since binding was created
- **Show keys / Hide keys** — toggles a list of all enrolled stable key JKT thumbprints (click any to copy)

**Actions:**
- **Revoke** — with a confirmation dialog that states how many devices will be affected. Permanently prevents token renewal. The agent must re-enroll to get a new binding.

Revoked bindings appear in a greyed-out **Revoked** section at the bottom of the page.

```bash
# See current state from curl:
curl -s http://localhost:8800/person/bindings \
  -H "Authorization: Bearer mytoken" | python3 -m json.tool
```

---

## 5. Testing with curl (insecure_dev mode)

Start the server with `AAUTH_AS_INSECURE_DEV=true` (see [§2](#2-start-the-server)). In this mode, the cryptographic signature bytes are **not verified**, but the headers are still **fully parsed** — the server extracts the ephemeral public key from `Signature-Key` and embeds it in the issued agent token as `cnf.jwk`.

> **Important:** Even in `insecure_dev` mode the `Signature-Input`, `Signature`, and `Signature-Key` headers must be present and structurally valid. The `x` field in `Signature-Key` must be a real base64url-encoded Ed25519 public key (43 chars, 32 bytes), because its value ends up in the token's `cnf.jwk`. Using a placeholder like all-zeros will produce a token with `cnf.jwk.x = "AAAA..."` — technically valid but useless for real signature verification.

Use the walkthrough script instead of hand-written `curl` snippets. It generates real Ed25519 keys, sends the same HTTP requests with a dummy `Signature`, checks status codes and JSON, decodes the JWT payload, and confirms `cnf.jwk.x` matches the ephemeral key you presented. It also covers re-registration (same stable key, new ephemeral key → immediate `200`), lists person endpoints, and optionally revokes the binding at the end.

From the repo root (with the server already running):

```bash
chmod +x scripts/agent-server-walkthrough.sh   # once

# --- Against the unified portal (port 8765) ---
# PENDING_POLL_PREFIX is required: the portal uses /register/pending/{id}
BASE=http://localhost:8765 PERSON_TOKEN=mytoken \
  PENDING_POLL_PREFIX=/register/pending \
  ./scripts/agent-server-walkthrough.sh

# Non-interactive against the portal:
AUTO=1 BASE=http://localhost:8765 PENDING_POLL_PREFIX=/register/pending \
  ./scripts/agent-server-walkthrough.sh

# --- Against the standalone Agent Server (port 8800, default) ---
# No PENDING_POLL_PREFIX needed (uses /pending/{id})
./scripts/agent-server-walkthrough.sh
BASE=http://localhost:8800 PERSON_TOKEN=mytoken ./scripts/agent-server-walkthrough.sh

# Non-interactive, standalone:
AUTO=1 ./scripts/agent-server-walkthrough.sh

# Core flow only (no re-register / list / revoke):
AUTO=1 SKIP_OPTIONAL=1 ./scripts/agent-server-walkthrough.sh
```

**Environment variables:**

| Variable | Default | Meaning |
|----------|---------|---------|
| `BASE` | `http://localhost:8800` | Server origin |
| `PERSON_TOKEN` | `mytoken` | Bearer for `/person/*` approve/deny/list |
| `PENDING_POLL_PREFIX` | `/pending` | Path prefix for the registration poll `GET` after `POST /register`. Use `/register/pending` for the unified portal; leave as `/pending` for standalone AS. |
| `AUTO` | `0` | Set to `1` to skip confirmation pauses |
| `SKIP_OPTIONAL` | `0` | Set to `1` to skip re-register, list, and revoke steps |

**Requirements:** `curl`, `openssl`, `python3` on `PATH`; `jq` is optional (prettier JSON in the script output).

**What you should see:** After approval, the decoded agent token payload includes `iss`, `sub` (agent id), `dwk`, `jti`, `cnf.jwk` (ephemeral OKP key), `iat`, and `exp`. The script verifies that `cnf.jwk.x` equals the ephemeral public key from your registration `Signature-Key` header.

---

## 6. Testing with real HTTP signatures (Python)

For end-to-end testing with **real** Ed25519 HTTP Message Signatures (`aauth.sign_request`), run the signed walkthrough script. It uses the `hwk` scheme for `POST /register` and the registration poll, then the `jkt-jwt` scheme for `POST /refresh` (see [§7](#7-token-renewal-refresh--jkt-jwt)). This matches how a production agent proves possession of keys.

**Server requirements (unlike [§5](#5-testing-with-curl-insecure_dev-mode)):**

- `AAUTH_AS_INSECURE_DEV=false` so signatures are verified.
- A persistent server signing key, e.g. `AAUTH_AS_SIGNING_KEY_PATH=./keys/signing.pem` (see [§2](#2-start-the-server)).
- For the portal: `AAUTH_PS_INSECURE_DEV=false`. The script asserts the issued token's `iss` equals the `issuer` in `/.well-known/aauth-agent.json`, which the portal sets to `AAUTH_PS_PUBLIC_ORIGIN`.

From the repo root, with project dependencies installed (`uv pip install -e .` or equivalent):

```bash
# --- Against the unified portal (port 8765) ---
AGENT_BASE=http://localhost:8765 PERSON_TOKEN=mytoken \
  .venv/bin/python scripts/agent-server-signed-walkthrough.py \
  --pending-prefix /register/pending

# --- Against the standalone Agent Server (port 8800, default) ---
AGENT_BASE=http://127.0.0.1:8800 PERSON_TOKEN=mytoken \
  .venv/bin/python scripts/agent-server-signed-walkthrough.py
```

**Environment variables** (optional; flags override):

| Variable | Default | Meaning |
|----------|---------|---------|
| `AGENT_BASE` | `http://localhost:8800` | Server origin (same as `--base`) |
| `PERSON_TOKEN` | `mytoken` | `AAUTH_AS_PERSON_TOKEN` for `/person/*` (same as `--person-token`) |
| `PENDING_POLL_PREFIX` | `/pending` | Registration poll path prefix (same as `--pending-prefix`). Use `/register/pending` for the unified portal. |

**CLI flags:**

| Flag | Effect |
|------|--------|
| `--base URL` | Server origin |
| `--person-token TOKEN` | Bearer for approve |
| `--skip-refresh` | Stop after the first `agent_token` (no `POST /refresh`) |
| `--pending-prefix PATH` | Override poll path prefix (default `/pending`; use `/register/pending` for portal) |

**What the script does**

1. Generates stable + ephemeral Ed25519 key pairs; prints the stable JKT (`urn:jkt:sha-256:…`).
2. `GET /.well-known/aauth-agent.json` — must return **200**; reads `issuer`.
3. `POST /register` with JSON body + `hwk` HTTP signature — expects **202**, `Location` header, body `{"status":"pending",…}`.
4. `GET <pending-prefix>/{id}` before approval — expects **202** and `{"status":"pending"}`.
5. `POST /person/registrations/{id}/approve` with `Authorization: Bearer …` — expects **200** and `agent_id`.
6. `GET <pending-prefix>/{id}` after approval — expects **200** and `agent_token`; decodes JWT and checks `iss`, `sub`, `dwk`, and that `cnf.jwk.x` matches the ephemeral key used at registration.
7. Unless `--skip-refresh`: builds `jkt-s256+jwt`, calls `POST /refresh` with `jkt-jwt` + new ephemeral signer — expects **200**; checks new token has same `sub` and new `cnf.jwk.x`.

The script uses **stdlib `urllib` only** (no `requests`). It exits with status **0** on success and **1** if any assertion or HTTP status fails.

**Example output** against the portal (IDs, times, and JWT strings differ each run):

```
Generating Ed25519 key pairs (stable + ephemeral)…
Stable JKT: urn:jkt:sha-256:QNHUodPC7m3FNtiY6g-1iZJky6Cym5eq8UAnf1Ewzew

--- GET /.well-known/aauth-agent.json ---
{
  "issuer": "http://localhost:8765",
  "jwks_uri": "http://localhost:8765/.well-known/jwks.json",
  "client_name": "AAuth Person Portal",
  ...
}

--- POST /register ---
HTTP 202  Location: /register/pending/i1YYnzNgbcpu1x__CdcXNg
{
  "status": "pending",
  "expires_at": "2026-04-23T16:41:27.530717+00:00"
}
Pending ID: i1YYnzNgbcpu1x__CdcXNg

--- GET /register/pending/{id} (before approval) ---
HTTP 202  {"status":"pending"}

--- POST /person/registrations/{id}/approve ---
{
  "agent_id": "aauth:efb305c4-f032-4895-82f8-579493831e17@localhost",
  "label": "Signed walkthrough client"
}

--- GET /register/pending/{id} (after approval) ---
HTTP 200  agent_token: eyJhbGciOiJFZERTQSIsImtpZCI6ImFzLTIwMjYwNC00Mjc4Mz…
Token claims (decoded, signature not verified):
{
  "iss": "http://localhost:8765",
  "sub": "aauth:efb305c4-f032-4895-82f8-579493831e17@localhost",
  "dwk": "aauth-agent.json",
  "jti": "f24843e6-4294-4497-9acd-8664604ee99d",
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "vIyQ-DWzXqw89utcbpT_sw4bKZyp-FFzxopYkj5UM7U"
    }
  },
  "iat": 1776958887,
  "exp": 1777045287
}

=== Registration + signed requests complete ===
Agent ID: aauth:efb305c4-f032-4895-82f8-579493831e17@localhost
Token exp: 1777045287 (86400s from now)

--- POST /refresh (jkt-jwt) ---
HTTP 200  new agent_token: eyJhbGciOiJFZERTQSIsImtpZCI6ImFzLTIwMjYwNC00Mjc4Mz…
New token cnf.jwk.x matches new ephemeral key.

=== Refresh (jkt-jwt) complete ===
```


---

## 7. Token Renewal (refresh / jkt-jwt)

Renewal uses the `jkt-jwt` HTTP signature scheme. The stable key signs a short-lived JWT that delegates to a new ephemeral key. No person interaction required. The runnable flow is implemented in `scripts/agent-server-signed-walkthrough.py` (after registration); use `--skip-refresh` if you only want to exercise registration.

**The `jkt-jwt` JWT structure:**

```
Header: {
  "alg": "EdDSA",
  "typ": "jkt-s256+jwt",       # MUST be jkt-s256+jwt
  "jwk": { <stable_pub JWK> }  # Stable public key embedded in header
}
Payload: {
  "iss": "urn:jkt:sha-256:<thumbprint>",  # JKT of the stable key
  "cnf": { "jwk": { <new_eph_pub JWK> } },
  "iat": <now>,
  "exp": <now + short_ttl>
}
Signed with: stable_priv
```

The HTTP request itself is then signed with `new_eph_priv`, carrying the above JWT in the `Signature-Key` header as `sig=jkt-jwt;jwt="..."` (built via `aauth.sign_request(..., sig_scheme="jkt-jwt", jwt=...)`).

### What the server verifies on refresh

1. Parses `Signature-Key: sig=jkt-jwt;jwt="..."` header
2. Decodes the JWT (without verifying first)
3. Extracts `stable_pub` from the JWT header `jwk`
4. Computes `urn:jkt:sha-256:<thumbprint>` of `stable_pub`
5. Verifies JWT `iss` matches the computed JKT
6. Verifies JWT signature using `stable_pub` → proves stable key possession
7. Extracts `cnf.jwk` (new ephemeral key) from JWT payload
8. Verifies HTTP `Signature` using the new ephemeral key → proves ephemeral key possession
9. Looks up binding by stable JKT; checks not revoked
10. Issues new agent token with same `sub`, new `cnf.jwk`

---

## 8. Multi-device: Linking a Second Device

When a second laptop needs to enroll under the same person identity, the person can **link** the new device's registration to an existing binding rather than creating a new `agent_id`.

### Scenario

- Device 1 already enrolled: `agent_id = aauth:abc@localhost`
- Device 2 registers with a different stable key

### Via the UI

1. Device 2 calls `POST /register` → a new pending card appears on the **Pending Registrations** page
2. The person clicks **Link to existing agent**
3. A modal appears listing active bindings — select the one for Device 1
4. Confirm: "This will add this device to [label]. The device will share the same agent identity."
5. Click **Link device**

Device 2 now polls `GET /pending/{id}` (standalone AS) or `GET /register/pending/{id}` (unified portal) and receives an agent token with the same `sub` as Device 1.

### Via the API

```bash
# Device 2 has pending_id = "xyz789"
# Existing binding agent_id = "aauth:abc@localhost"

curl -s -X POST "$BASE/person/registrations/xyz789/link" \
  -H "Authorization: Bearer $PERSON_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "aauth:abc@localhost"}' | jq .
```

Expected:
```json
{
  "agent_id": "aauth:abc@localhost",
  "label": "MacBook Air"
}
```

**Error cases:**
- `404` if the pending registration or target binding doesn't exist
- `409` if the device's stable key is already on the target binding

After linking, Device 2 polls and gets a token with `sub = aauth:abc@localhost`.

---

## 9. Revocation

Revoking a binding prevents all devices enrolled under it from renewing tokens. They can still use any unexpired tokens they already hold (tokens are not invalidated at resource servers — that requires a revocation endpoint at the resource, which is out of scope here). On the next `/refresh` attempt they'll get a 401.

### Via the UI

On **My Agents** (`/ui/agents.html`), click **Revoke** next to the binding. The confirmation dialog shows how many devices will be affected.

### Via the API

```bash
# URL-encode the agent_id
AGENT_ID="aauth:abc@localhost"
ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$AGENT_ID'))")

curl -s -X POST "$BASE/person/bindings/$ENCODED/revoke" \
  -H "Authorization: Bearer $PERSON_TOKEN"
```

Response: `200 OK`

### Verify revocation

```bash
# Check the binding is marked revoked
curl -s "$BASE/person/bindings" \
  -H "Authorization: Bearer $PERSON_TOKEN" | jq '.[] | select(.agent_id == "aauth:abc@localhost")'
```

Expected:
```json
{
  "agent_id": "aauth:abc@localhost",
  "revoked": true,
  ...
}
```

A revoked agent trying to refresh:
```bash
# POST /refresh with the revoked binding's stable key
# → 401 Unauthorized
```

---

## 10. Verifying an Issued Agent Token

### Check signature against server JWKS

```python
import requests
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import aauth

BASE = "http://localhost:8800"
agent_token = "eyJ..."  # paste your token here

# Fetch server's public JWKS
jwks = requests.get(f"{BASE}/.well-known/jwks.json").json()

# Parse the token header to find the kid
header = pyjwt.get_unverified_header(agent_token)
kid = header.get("kid")
print(f"Token signed with kid: {kid}")

# Find matching key
key_jwk = next((k for k in jwks["keys"] if k["kid"] == kid), None)
assert key_jwk, f"Key {kid} not found in JWKS"

# Convert JWK to public key object
pub_key = aauth.jwk_to_public_key(key_jwk)

# Verify signature
import base64
parts = agent_token.split(".")
signing_input = f"{parts[0]}.{parts[1]}".encode()
sig = base64.urlsafe_b64decode(parts[2] + "==")
pub_key.verify(sig, signing_input)
print("Signature VALID")

# Decode and print claims
payload = pyjwt.decode(agent_token, options={"verify_signature": False})
import json
print(json.dumps(payload, indent=2))
```

### What a resource server checks

When an agent presents its token to a resource, the resource should verify:

1. `typ` = `aa-agent+jwt`
2. `dwk` = `aauth-agent.json`
3. `iss` is the expected agent server URL
4. Signature against `{iss}/.well-known/jwks.json` (matching `kid`)
5. `exp` is in the future
6. The HTTP request itself is signed with the private key corresponding to `cnf.jwk`

---

## 11. API Reference

### Agent-facing endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/.well-known/aauth-agent.json` | None | Server metadata |
| `GET` | `/.well-known/jwks.json` | None | Server's signing public keys |
| `POST` | `/register` | HTTP Sig (`hwk`) | Self-register. Body: `{stable_pub, label?}`. Returns `202` with `Location` or `200` with `agent_token` (re-registration). |
| `GET` | `/pending/{id}` | HTTP Sig (`hwk`, same eph key) | Poll for approval. `202` pending, `200` approved (includes `agent_token`), `403` denied, `410` expired. **Standalone AS only.** |
| `GET` | `/register/pending/{id}` | HTTP Sig (`hwk`, same eph key) | Same as above — **unified portal only**. The portal mounts the registration poll at this path to avoid conflict with the Person Server's `/pending/{id}` token-broker endpoint. |
| `POST` | `/refresh` | HTTP Sig (`jkt-jwt`) | Renew token. Empty body. Returns `200` with `agent_token`. |

### Person-facing endpoints

All require `Authorization: Bearer <AAUTH_AS_PERSON_TOKEN>`.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/person/registrations` | List pending registrations |
| `POST` | `/person/registrations/{id}/approve` | Approve → creates binding → returns `{agent_id, label}` |
| `POST` | `/person/registrations/{id}/deny` | Deny registration |
| `POST` | `/person/registrations/{id}/link` | Link to existing binding. Body: `{agent_id}`. Returns `{agent_id, label}`. `409` if already linked. |
| `GET` | `/person/bindings` | List all bindings (active + revoked) |
| `POST` | `/person/bindings/{agent_id}/revoke` | Revoke binding |

### HTTP signature headers (agent requests)

All agent-facing requests require these three headers:

```
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=<unix_ts>
Signature: sig=:<base64url-encoded Ed25519 signature>:
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="<base64url pub key>"
             # or for refresh:
             # sig=jkt-jwt;jwt="<jkt-s256+jwt compact JWT>"
```

### Status codes

| Code | Meaning |
|------|---------|
| `200` | Success (agent token or binding details) |
| `202` | Pending (agent registration queued; poll `Location`) |
| `401` | Signature verification failed |
| `403` | Denied (person rejected the registration, or binding revoked) |
| `404` | Pending registration or binding not found |
| `409` | Conflict (stable key already on target binding) |
| `410` | Expired (pending registration timed out) |

---

## 12. Troubleshooting

### `401 Unauthorized` on `/register` or `/pending/{id}` (or `/register/pending/{id}`)

- **insecure_dev=true**: Check that `Signature-Input`, `Signature`, and `Signature-Key` headers are present. The key `x` value must be a valid base64url string (44 characters for Ed25519).
- **insecure_dev=false**: Verify the `created` timestamp in `Signature-Input` is within 60 seconds of server time. Ensure the HTTP signature covers `@method`, `@authority`, `@path`, and `signature-key`.
- For the registration poll: the `Signature-Key` must use the **same** ephemeral key that was used at registration. Using a different ephemeral key returns 401.
- **Portal path confusion:** if running the walkthrough scripts against the unified portal without `PENDING_POLL_PREFIX=/register/pending` (bash) or `--pending-prefix /register/pending` (Python), the script will poll `/pending/{id}` which hits the Person Server token-broker and return 404. Set the correct prefix.

### `410 Gone` on `GET /pending/{id}` (or `/register/pending/{id}`)

The pending registration expired (default TTL is 1 hour). Re-register with `POST /register`.

### `404` on `GET /pending/{id}` (or `/register/pending/{id}`)

The pending ID is unknown. Either the server restarted (in-memory state is lost), the ID is wrong, or you are polling the wrong path — use `/register/pending/{id}` for the unified portal and `/pending/{id}` for standalone AS.

### `401` on `POST /refresh`

- The stable key's JKT is not in any active binding. The agent may need to re-register.
- The binding was revoked.
- The JWT or HTTP signature verification failed. Ensure the `jkt-jwt` JWT `typ` is `jkt-s256+jwt`, the JWT header contains `jwk` with the stable public key, the JWT `iss` is `urn:jkt:sha-256:<correct-thumbprint>`, and the JWT is not expired.

### Server restarts wipe all state

The reference implementation is in-memory. Set `AAUTH_AS_SIGNING_KEY_PATH` so at least the signing key survives restarts — this preserves the ability to verify previously issued tokens. Bindings and pending registrations are lost on restart.

### `cnf.jwk.x` in the issued token is all zeros

You ran the server with `insecure_dev=true` and either passed a placeholder key value or ran an older version of the code. The server now parses the actual `Signature-Key` header even in dev mode, so the token's `cnf.jwk` reflects whatever public key you put in `Signature-Key`. Use a real Ed25519 key in `Signature-Key` (see section 5 for the `openssl` commands).

### `WARNING: AAUTH_AS_PERSON_TOKEN is set to the default value`

Change the `AAUTH_AS_PERSON_TOKEN` environment variable to a strong random string before using this server on a network.

### Person token returns `403` but I know it's right

Bearer tokens are compared with exact string equality, including leading/trailing spaces. Make sure there's no whitespace in the token value.

### OpenAPI docs

The interactive API docs are available at `http://localhost:8800/docs` — useful for exploring the schema and trying requests in the browser.
