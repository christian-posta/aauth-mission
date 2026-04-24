# AAuth Person Portal Reference

Reference implementation of:

- a Person Server (`ps.http.app`)
- an Agent Server (`agent_server.http.app`)
- a unified portal that serves both on one origin (`portal.http.app`)

The unified portal is the main entrypoint now. It combines mission, token, consent, registration, binding, and refresh flows behind one UI and one set of well-known endpoints. Running **only** the Person Server or **only** the Agent Server (original ports, UIs, and script invocations) is documented in one place below: [Standalone Person Server and Agent Server](#standalone-person-server-and-agent-server).

## What Changed

The latest commit (`c67bd63`, `first crack unifying PS and AgentServer to a single UI/UX`) introduced the new `portal/` app, portal UI pages, and the route split needed to host Person Server and Agent Server behavior on the same origin.

Important behavior change:

- Person Server pending URLs still use `GET /pending/{id}`.
- Agent registration polling uses `GET /register/pending/{id}` in the portal.
- Standalone Agent Server still uses `GET /pending/{id}`.

## Verified Paths

On April 23, 2026, the commands and scripts below were re-run successfully against this repo:

- `pytest`
- `./scripts/ps-demo.sh`
- `./scripts/hwk-ps-client.sh`
- `.venv/bin/python scripts/ps-token-mode3.py` (portal with `AAUTH_PS_INSECURE_DEV=false`, `AAUTH_AS_INSECURE_DEV=true`; `AAUTH_PS_AUTO_APPROVE_TOKEN` optional if the minted resource scope omits `require:user`; see script docstring)
- `./scripts/agent-server-walkthrough.sh`
- `.venv/bin/python scripts/agent-server-signed-walkthrough.py`

They were verified against the unified portal, and the agent walkthroughs were also verified against the standalone Agent Server (see [Standalone Person Server and Agent Server](#standalone-person-server-and-agent-server)).

## Install

With `uv`:

```bash
cd /path/to/aauth-person-server
uv venv .venv
uv pip install --python .venv/bin/python -e ".[dev]"
```

With plain `venv` + `pip`:

```bash
cd /path/to/aauth-person-server
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Unified Portal

Start the combined app:

```bash
cd /path/to/aauth-person-server
source .venv/bin/activate

export AAUTH_PS_PUBLIC_ORIGIN=http://127.0.0.1:8765
export AAUTH_AS_PUBLIC_ORIGIN=http://127.0.0.1:8765
export AAUTH_PS_ADMIN_TOKEN=mytoken
export AAUTH_AS_PERSON_TOKEN=mytoken

# Dev mode: stub PS agent identity + skip AS signature verification
export AAUTH_PS_INSECURE_DEV=true
export AAUTH_AS_INSECURE_DEV=true

uvicorn portal.http.app:app --reload --host 127.0.0.1 --port 8765
```

Useful URLs:

- Portal login: `http://127.0.0.1:8765/ui/index.html`
- Portal dashboard: `http://127.0.0.1:8765/ui/portal.html`
- Consent page: `http://127.0.0.1:8765/ui/consent.html`
- Person metadata: `http://127.0.0.1:8765/.well-known/aauth-person.json`
- Agent metadata: `http://127.0.0.1:8765/.well-known/aauth-agent.json`
- Signing JWKS: `http://127.0.0.1:8765/.well-known/jwks.json`

Sign into the portal with the value of `AAUTH_PS_ADMIN_TOKEN` / `AAUTH_AS_PERSON_TOKEN`.

## Walkthrough Scripts (unified portal)

The commands below assume the portal is running on `http://127.0.0.1:8765` unless a snippet says otherwise.

**Agent registration from the command line:** there are two modes. **`./scripts/agent-server-walkthrough.sh`** only works when **`AAUTH_AS_INSECURE_DEV=true`** (it sends stub signature bytes). With **`AAUTH_AS_INSECURE_DEV=false`**, Agent Server routes verify real HTTP message signatures — use **`scripts/agent-server-signed-walkthrough.py`** instead ([§ Agent Server Walkthrough (real signatures)](#agent-server-walkthrough-real-signatures)), with both `AAUTH_PS_INSECURE_DEV` and `AAUTH_AS_INSECURE_DEV` set to `false` if you want HWK verified on Person Server routes too.

For the quick-start env from [Unified Portal](#unified-portal) (both insecure flags `true`), use the shell walkthrough as written. For running the same scripts against **only** `ps.http.app` or **only** `agent_server.http.app`, see [Standalone Person Server and Agent Server](#standalone-person-server-and-agent-server).

### Person Server Demo

`./scripts/ps-demo.sh` exercises the dev-mode Person Server flow:

- `GET /.well-known/aauth-person.json`
- `POST /mission`
- `POST /permission`
- `POST /audit`
- `POST /token`
- `GET /consent`
- `POST /consent/{pending_id}/decision`
- `GET /pending/{id}`
- `DELETE /pending/{id}`

```bash
BASE_URL=http://127.0.0.1:8765 ./scripts/ps-demo.sh
```

`jq` is optional but makes the output easier to read.

### HWK Person Server Client

`./scripts/hwk-ps-client.sh` uses real HWK signing for Person Server routes. It delegates to `scripts/_hwk_ps_client.py`, creates or reuses an Ed25519 PEM key, and can drive:

- `POST /mission`
- `POST /permission`
- `POST /audit`
- `POST /token`
- optional `POST /interaction` completion

For this script, Person Server signature verification must be enabled on the process you hit (portal includes both stacks):

```bash
AAUTH_PS_PUBLIC_ORIGIN=http://127.0.0.1:8765 \
AAUTH_AS_PUBLIC_ORIGIN=http://127.0.0.1:8765 \
AAUTH_PS_ADMIN_TOKEN=mytoken \
AAUTH_AS_PERSON_TOKEN=mytoken \
AAUTH_PS_INSECURE_DEV=false \
AAUTH_AS_INSECURE_DEV=false \
uvicorn portal.http.app:app --host 127.0.0.1 --port 8765
```

Then run:

```bash
./scripts/hwk-ps-client.sh --base-url http://127.0.0.1:8765 --permission-action WebSearch --audit
```

Notes:

- The script intentionally pauses on deferred consent and polls until the user approves.
- Approve in the portal UI, or call `GET /consent?code=...` followed by `POST /consent/{pending_id}/decision`.
- With **`AAUTH_PS_INSECURE_DEV=true`**, a successful completion returns a **fake** `auth_token` string (`aa-auth.fake.*`), not a JWT.
- With **`AAUTH_PS_INSECURE_DEV=false`** (production-style), **`POST /token`** requires **`scheme=jwt`** and a verifiable **`aa-resource+jwt`**; the response **`auth_token`** is a real **`aa-auth+jwt`** (see **`CLIENTS.md`** § mode 3 and **`scripts/ps-token-mode3.py`**).

### Agent Server Walkthrough (insecure dev)

`./scripts/agent-server-walkthrough.sh` verifies the registration and approval flow using structurally valid signature headers while **`AAUTH_AS_INSECURE_DEV=true`**. If the portal is started with **`AAUTH_AS_INSECURE_DEV=false`**, `POST /register` returns **401** for this script — that is expected; switch to [Agent Server Walkthrough (real signatures)](#agent-server-walkthrough-real-signatures).

```bash
AUTO=1 \
BASE=http://127.0.0.1:8765 \
PERSON_TOKEN=mytoken \
PENDING_POLL_PREFIX=/register/pending \
./scripts/agent-server-walkthrough.sh
```

The script verifies:

- `POST /register`
- poll before approval
- `POST /person/registrations/{id}/approve`
- poll after approval
- JWT payload structure
- `cnf.jwk.x` matches the registration key
- re-registration with the same stable key
- `/person/registrations`
- `/person/bindings`

Optional env vars:

- `AUTO=1` skips pauses.
- `SKIP_OPTIONAL=1` skips re-register/list/revoke extras.
- `PENDING_POLL_PREFIX=/register/pending` is required for the portal (registration poll lives under `/register/pending`, not `/pending`).

### Agent Server Walkthrough (real signatures)

`scripts/agent-server-signed-walkthrough.py` uses real `aauth.sign_request(...)` calls:

- `hwk` for registration and poll
- `jkt-jwt` for refresh

Start the portal with signatures enforced, then:

```bash
AAUTH_PS_PUBLIC_ORIGIN=http://127.0.0.1:8765 \
AAUTH_AS_PUBLIC_ORIGIN=http://127.0.0.1:8765 \
AAUTH_PS_ADMIN_TOKEN=mytoken \
AAUTH_AS_PERSON_TOKEN=mytoken \
AAUTH_PS_INSECURE_DEV=false \
AAUTH_AS_INSECURE_DEV=false \
uvicorn portal.http.app:app --host 127.0.0.1 --port 8765
```

```bash
.venv/bin/python scripts/agent-server-signed-walkthrough.py \
  --base http://127.0.0.1:8765 \
  --person-token mytoken \
  --pending-prefix /register/pending
```

The script verifies:

- `GET /.well-known/aauth-agent.json`
- `POST /register`
- poll before approval
- approval via `/person/registrations/{id}/approve`
- agent token issuance
- decoded token claims
- `POST /refresh`
- refreshed token keeps the same `sub` and rotates `cnf.jwk`

## Standalone Person Server and Agent Server

Use these when you want **only** the Person Server or **only** the Agent Server (isolated ports, original UIs, original registration poll path `GET /pending/{id}` on AS). Full agent-server flows and env tables remain in **AGENTSERVER.md**.

### Standalone Person Server (`ps.http.app`)

```bash
AAUTH_PS_PUBLIC_ORIGIN=http://127.0.0.1:8766 \
AAUTH_PS_INSECURE_DEV=true \
uvicorn ps.http.app:app --reload --host 127.0.0.1 --port 8766
```

**`ps-demo.sh`** against standalone PS:

```bash
BASE_URL=http://127.0.0.1:8766 ./scripts/ps-demo.sh
```

**`hwk-ps-client.sh`** against standalone PS (start with `AAUTH_PS_INSECURE_DEV=false` only on the PS process):

```bash
AAUTH_PS_INSECURE_DEV=false uvicorn ps.http.app:app --host 127.0.0.1 --port 8766
```

```bash
./scripts/hwk-ps-client.sh --base-url http://127.0.0.1:8766 --permission-action WebSearch --audit
```

Static PS console (when running standalone): `http://127.0.0.1:8766/ui/` (`index.html`, `user.html`, `admin.html` — sources under `ps/http/static/`; behavior in **SPEC.md**).

### Standalone Agent Server (`agent_server.http.app`)

```bash
AAUTH_AS_PUBLIC_ORIGIN=http://127.0.0.1:8800 \
AAUTH_AS_ISSUER=http://127.0.0.1:8800 \
AAUTH_AS_SERVER_DOMAIN=localhost \
AAUTH_AS_PERSON_TOKEN=mytoken \
AAUTH_AS_INSECURE_DEV=true \
uvicorn agent_server.http.app:app --reload --host 127.0.0.1 --port 8800
```

UI:

- `http://127.0.0.1:8800/ui/index.html`
- `http://127.0.0.1:8800/ui/registrations.html`
- `http://127.0.0.1:8800/ui/agents.html`

**`agent-server-walkthrough.sh`** (default poll prefix `/pending`; no `PENDING_POLL_PREFIX` needed):

```bash
AUTO=1 \
BASE=http://127.0.0.1:8800 \
PERSON_TOKEN=mytoken \
./scripts/agent-server-walkthrough.sh
```

**`agent-server-signed-walkthrough.py`** with real signatures:

```bash
AAUTH_AS_PUBLIC_ORIGIN=http://127.0.0.1:8800 \
AAUTH_AS_ISSUER=http://127.0.0.1:8800 \
AAUTH_AS_SERVER_DOMAIN=localhost \
AAUTH_AS_PERSON_TOKEN=mytoken \
AAUTH_AS_INSECURE_DEV=false \
uvicorn agent_server.http.app:app --host 127.0.0.1 --port 8800
```

```bash
.venv/bin/python scripts/agent-server-signed-walkthrough.py \
  --base http://127.0.0.1:8800 \
  --person-token mytoken
```

## Environment

### Person Server / Portal (`AAUTH_PS_*`)

| Variable | Default | Meaning |
|----------|---------|---------|
| `AAUTH_PS_PUBLIC_ORIGIN` | `http://localhost:8765` | Public base URL for metadata and consent links. |
| `AAUTH_PS_INSECURE_DEV` | `true` | Accept `X-AAuth-Agent-Id` instead of verifying HWK signatures. |
| `AAUTH_PS_ADMIN_TOKEN` | unset | Bearer token for `/missions` and `/admin/pending`. If unset, admin routes are open. |
| `AAUTH_PS_USER_TOKEN` | unset | Enables `/user/*` routes. |
| `AAUTH_PS_USER_ID` | `user` | Owner id returned for the configured legal-user token. |
| `AAUTH_PS_AUTO_APPROVE_TOKEN` | `false` | If `true`, skip all consent on `POST /token`. If `false` (secure mode), consent runs only when the verified resource token `scope` includes `require:user` (space-separated); otherwise the auth token is issued immediately. |
| `AAUTH_PS_AUTO_APPROVE_MISSION` | `true` | If `false`, mission creation is deferred for approval. |
| `AAUTH_PS_PENDING_TTL_SECONDS` | `600` | TTL for open Person Server pending rows. |
| `AAUTH_PS_JWKS_URI` | unset | Override `jwks_uri` in Person metadata. |
| `AAUTH_PS_SIGNING_KEY_PATH` | `./.aauth/ps-signing-key.pem` | PS Ed25519 key PEM for **`aa-auth+jwt`**; generated on first boot. Set to empty string for an ephemeral in-memory key (tests only). |
| `AAUTH_PS_TRUST_FILE` | `./.aauth/ps-trusted-agents.json` | Optional JSON persistence for the **Trusted Agent Servers** registry. Empty string disables persistence. |
| `AAUTH_PS_AUTH_TOKEN_LIFETIME` | `3600` | Lifetime (seconds) for PS-issued auth JWTs (max 1h per SPEC). |

**Trust policy** for agent token issuers (mode 3) is documented in **`TRUST.md`**. **Client wire format** for secure **`POST /token`** is in **`CLIENTS.md`** (§ Person Server as authorization server).

### Agent Server / Portal (`AAUTH_AS_*`)

| Variable | Default | Meaning |
|----------|---------|---------|
| `AAUTH_AS_PUBLIC_ORIGIN` | `http://localhost:8800` | Public base URL for agent metadata. In the portal, this is effectively aligned to `AAUTH_PS_PUBLIC_ORIGIN`. |
| `AAUTH_AS_ISSUER` | `https://agent-server.example` | `iss` claim for issued agent tokens. In the portal, issuer is aligned to the portal origin. |
| `AAUTH_AS_SERVER_DOMAIN` | `agent-server.example` | Domain suffix for generated `aauth:<uuid>@<domain>` ids. |
| `AAUTH_AS_PERSON_TOKEN` | `changeme` | Bearer token for `/person/*`. |
| `AAUTH_AS_INSECURE_DEV` | `false` | Skip Agent Server HTTP signature verification. |
| `AAUTH_AS_SIGNING_KEY_PATH` | unset | Persistent Ed25519 signing key for agent tokens. |
| `AAUTH_AS_PREVIOUS_KEY_PATH` | unset | Previous signing key kept in JWKS during rotation. |
| `AAUTH_AS_AGENT_TOKEN_LIFETIME` | `86400` | Agent token lifetime in seconds. |
| `AAUTH_AS_REGISTRATION_TTL` | `3600` | TTL for pending registrations. |
| `AAUTH_AS_SIGNATURE_WINDOW` | `60` | Allowed skew for HTTP signature timestamps. |
| `AAUTH_AS_CLIENT_NAME` | `AAuth Agent Server` | Well-known metadata display name. The portal sets this to `AAuth Person Portal`. |

## API Surface

### Person Server endpoints

- `GET /.well-known/aauth-person.json`
- `GET /.well-known/jwks.json` — PS signing JWKS (portal merges Person Server + Agent Server keys at this path)
- `POST /mission`
- `POST /token` — With **`AAUTH_PS_INSECURE_DEV=false`**, requires **`Signature-Key`** **`scheme=jwt`** (see **`CLIENTS.md`** mode 3); with **`true`**, HWK or **`X-AAuth-Agent-Id`** still accepted for demos.
- `POST /permission`
- `POST /audit`
- `POST /interaction`
- `GET /consent?code=...`
- `POST /consent/{pending_id}/decision`
- `GET /pending/{pending_id}`
- `POST /pending/{pending_id}`
- `DELETE /pending/{pending_id}`
- `GET /missions`
- `GET /missions/{s256}`
- `PATCH /missions/{s256}`
- `GET /user/missions`
- `GET /user/missions/{s256}`
- `PATCH /user/missions/{s256}`
- `GET /user/consent`
- `GET /admin/pending`
- `GET /person/trusted-agent-servers` — list trusted agent-server issuers (admin auth when configured)
- `POST /person/trusted-agent-servers` — add trusted issuer (probes `aauth-agent.json` + JWKS)
- `DELETE /person/trusted-agent-servers?issuer=...` — remove trusted issuer

### Agent Server endpoints

- `GET /.well-known/aauth-agent.json`
- `GET /.well-known/jwks.json`
- `POST /register`
- `POST /refresh`
- standalone poll: `GET /pending/{pending_id}`
- portal poll: `GET /register/pending/{pending_id}`
- `GET /person/registrations`
- `POST /person/registrations/{id}/approve`
- `POST /person/registrations/{id}/deny`
- `POST /person/registrations/{id}/link`
- `GET /person/bindings`
- `POST /person/bindings` — create a binding from a stable public JWK (`stable_pub` + required `agent_name`); the agent still calls `POST /register` to obtain a token
- `POST /person/bindings/{agent_id}/revoke`

## Tests

Run the smoke tests:

```bash
pytest
```

Coverage includes [tests/test_ps_api_smoke.py](tests/test_ps_api_smoke.py) (Person Server), [tests/test_ps_token_endpoint.py](tests/test_ps_token_endpoint.py) (mode-3 **`POST /token`**), and [tests/test_agent_server_register.py](tests/test_agent_server_register.py) (Agent Server `agent_name` / registration body validation).
