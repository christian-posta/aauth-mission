# Agent-server trust (Person Server mode 3)

When **`AAUTH_PS_INSECURE_DEV=false`**, `POST /token` verifies an **`aa-agent+jwt`** carried in `Signature-Key` with **`scheme=jwt`**. The Person Server resolves the agent token issuer’s JWKS only if that issuer is **trusted**.

## Rules

1. **Implicit self-trust** — If `agent_token["iss"]` equals the Person Server’s own origin (`AAUTH_PS_PUBLIC_ORIGIN`, no trailing slash), the PS uses the **co-located Agent Server JWKS** (unified portal) or, in a standalone PS process with no Agent Server, verification fails because no local JWKS is available.

2. **Registered issuers** — Any other issuer must appear in the **Trusted Agent Servers** registry (runtime-only; no environment seed list). Operators add issuers via:
   - `GET|POST|DELETE /person/trusted-agent-servers` (Person Server: bearer **`AAUTH_PS_ADMIN_TOKEN`** when set; unified portal: same routes are mounted with **`require_portal_admin`** in `portal/http/app.py`).

3. **Otherwise** — Requests fail with **`401`** and structured error **`invalid_agent_token`** (see `ps.exceptions.AgentTokenRejectError` and `ps/http/errors.py`).

## Add workflow

`POST /person/trusted-agent-servers` accepts an issuer URL, probes `{issuer}/.well-known/aauth-agent.json`, resolves **`jwks_uri`**, fetches JWKS, and stores **`display_name`**, **`jwks_uri`**, and a **JWKS fingerprint** (from `ps/api/trust_routes.py`). The self-origin is listed in the UI as immutable implicit trust and is not stored in the registry file.

## JWKS caching

`ps/federation/agent_jwks.py` (`AgentServerJWKSResolver`) caches JWKS per issuer with a TTL (default **300s**). External rotations change the served JWKS; operators should compare fingerprints shown in the admin UI after (re-)adding trust.

## Rotation and removal

- **Rotate AS keys** — Update the Agent Server JWKS; after cache TTL the PS picks up new keys. If you track fingerprints in the registry row, refresh the entry if your operational model requires it.
- **Remove trust** — `DELETE /person/trusted-agent-servers?issuer=...` removes the issuer; subsequent tokens from that issuer are rejected with **`invalid_agent_token`**.

## Persistence

Optional **`AAUTH_PS_TRUST_FILE`** (JSON on disk) survives process restarts for development; production deployments should treat the registry as operator-managed state.

## See also

- **`CLIENTS.md`** — HTTP shapes for agents and **Person Server mode 3** token requests.
- **`README.md`** — Environment variables **`AAUTH_PS_SIGNING_KEY_PATH`**, **`AAUTH_PS_TRUST_FILE`**, and **`AAUTH_PS_INSECURE_DEV`**.
