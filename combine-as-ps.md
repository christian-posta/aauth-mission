# Plan: Unified Person Portal (Single Backend + Single UI)

## Context

Currently there are two separate FastAPI servers, each with their own UI:
- **Person Server (PS)** on port 8765 — missions, token requests, consent flows
- **Agent Server (AS)** on port 8800 — agent device registrations and bindings

The unified portal runs on one port with a single "Person Portal" dashboard. The person is the owner/admin. There is **one role** ("person"), not separate admin/user. The dashboard has **3 tabs**:

1. **Agents** — manage agent device registrations (approve/deny/link) + active bindings (revoke)
2. **Missions** — view, inspect, and terminate all missions
3. **Token Requests** — pending items requiring person involvement (consent queue + open pending)

All existing PS and AS logic is preserved and untouched. The standalone PS and AS servers remain fully runnable.

---

## Route Conflict Resolution

| Conflict | Resolution |
|---|---|
| `GET/POST/DELETE /pending/{id}` (PS token-broker vs AS registration-poll) | AS's registration-polling path becomes `/register/pending/{id}` in the combined app only; standalone AS keeps `/pending/{id}` unchanged |
| `GET /.well-known/jwks.json` (both) | Return the AS's real Ed25519 JWKS — PS's was always `{"keys": []}` stub |

---

## Auth Simplification

The portal uses a **single person token** backed by `AAUTH_PS_ADMIN_TOKEN`. In `portal/http/app.py`:
- Define `require_portal_person(settings, authorization)` dep that validates against `AAUTH_PS_ADMIN_TOKEN`
- All person-facing routes in the combined app use this single dep (replaces `require_admin`, `require_user`, and `require_person` from respective apps)
- `AAUTH_AS_PERSON_TOKEN` still protects `/person/*` raw API routes (for direct API / script use)
- Login: enter the admin token → probes `GET /missions` → redirect to `portal.html`

---

## New Files to Create

### `portal/__init__.py` and `portal/http/__init__.py`
Empty package markers.

### `portal/http/app.py`
Combined FastAPI app factory `create_portal_app()`:

1. Instantiates `PSHttpSettings` (reads `AAUTH_PS_*`) and `AgentServerSettings` (reads `AAUTH_AS_*`)
2. Instantiates `PSContainer` via `build_memory_ps()` and `ASContainer` via `build_memory_as()`
3. Registers all exception handlers from both apps
4. Registers **all PS routes** (same as `ps/http/app.py`) using `require_portal_person` where applicable
5. Registers **all AS agent-facing routes** (register, refresh) and person-facing routes (`/person/registrations`, `/person/bindings`) with one change: AS's `GET /pending/{id}` becomes `GET /register/pending/{id}`
6. AS well-known `registration_endpoint` updated to reference `/register/pending/` path
7. `/.well-known/jwks.json` returns `as_.signing.get_jwks()` (real AS keys instead of empty stub)
8. Mounts `portal/ui/` at `/ui`

The combined app exposes all existing endpoints from both servers. No new bridge routes needed — the portal UI calls the existing AS `/person/registrations` and `/person/bindings` directly (both protected by `require_portal_person`).

### `portal/ui/index.html`
Portal login page:
- Single token field
- Probes `GET /missions` with token
- On success: store token as "person" role, redirect to `portal.html`
- Uses `js/auth.js` and `js/api.js`

### `portal/ui/portal.html`
3-tab unified dashboard using Alpine.js + Tailwind:

**Tab 1 — Agents:**
- "Pending Registrations" section: `GET /person/registrations` — cards with Approve / Deny / Link-to-existing actions (identical to `agent_server/ui/registrations.html` functionality)
- "Active Agents" section: `GET /person/bindings` — table with agent_id, device count, revoke button

**Tab 2 — Missions:**
- State filter (All / Active / Terminated)
- `GET /missions` — table with s256, agent_id, owner, state, created_at
- Click row → detail modal with mission JSON + log + Terminate button (`PATCH /missions/{s256}`)

**Tab 3 — Token Requests:**
- "Open Pending" section: `GET /admin/pending` — table showing deferred token/mission flows with Consent links that open `consent.html`
- Auto-refresh every 10s

### `portal/ui/consent.html`
Copy of `ps/http/static/consent.html` (the consent/interaction approval flow — already fully functional, no changes needed to logic).

### `portal/ui/js/auth.js`
Single-role auth helper (`PortalAuth` namespace):
- `getToken()`, `setSession(token)`, `getRole()`, `clear()`, `requireRole(loginPath)`
- Role is always "person"

### `portal/ui/js/api.js`
API client (`PortalApi` namespace):
- `fetch(path, opts)` — adds Bearer token
- `fetchJson(path, opts)` — wraps fetch with JSON parsing and error handling
- `relativeTime(isoString)` — relative time display (from AS's api.js)
- `copyToClipboard(text)` — clipboard helper (from AS's api.js)

---

## Files Left Completely Unchanged

- `ps/http/app.py` — standalone PS still fully runnable on its own port
- `ps/http/static/` — all files (index.html, admin.html, user.html, consent.html, js/) unchanged
- `agent_server/http/app.py` — standalone AS still fully runnable (keeps `/pending/{id}`)
- `agent_server/ui/` — all UI files unchanged
- All `ps/impl/`, `ps/service/`, `ps/models.py`, `ps/api/` — untouched
- All `agent_server/impl/`, `agent_server/service/`, `agent_server/models.py`, `agent_server/api/` — untouched
- `tests/` — existing smoke tests still pass (target standalone PS)
- `pyproject.toml` — no new dependencies

### Minor update: `scripts/agent-server-walkthrough.sh` and `agent-server-signed-walkthrough.py`
Change the one `/pending/{id}` reference → `/register/pending/{id}` when targeting the unified portal. Add a note that standalone AS still uses `/pending/{id}`.

---

## Critical Files Referenced

| File | Purpose |
|---|---|
| `ps/http/app.py` | Source of all PS route handlers to replicate in portal |
| `agent_server/http/app.py` | Source of all AS route handlers to replicate in portal |
| `ps/http/deps.py` | `require_admin`, `require_user`, `require_agent_id` — reused or adapted |
| `agent_server/http/deps.py` | `require_person`, `require_http_sig` — reused or adapted |
| `ps/impl/__init__.py` | `build_memory_ps()`, `PSContainer` |
| `agent_server/impl/__init__.py` | `build_memory_as()`, `ASContainer` |
| `agent_server/api/person_routes.py` | `handle_list_registrations`, `handle_approve`, `handle_deny`, `handle_link`, `handle_list_bindings`, `handle_revoke_binding` |
| `ps/http/static/consent.html` | Consent flow to copy verbatim into `portal/ui/` |
| `agent_server/ui/registrations.html` | Reference for Agents tab pending-registrations UX |

---

## Run Command

```bash
# Unified portal (replaces both servers):
export AAUTH_PS_PUBLIC_ORIGIN=http://localhost:8765
export AAUTH_AS_PUBLIC_ORIGIN=http://localhost:8765
export AAUTH_PS_ADMIN_TOKEN=mytoken
export AAUTH_PS_INSECURE_DEV=true
export AAUTH_AS_PERSON_TOKEN=mytoken   # same value for convenience
uvicorn portal.http.app:app --reload --host 0.0.0.0 --port 8765
```

---

## Verification

1. Start portal: `uvicorn portal.http.app:app --port 8765 --reload`
2. Open `http://localhost:8765/ui/index.html`
3. Sign in with admin token → redirected to `portal.html`
4. **Agents tab**: empty initially; run `scripts/agent-server-walkthrough.sh` (updated paths) → registration appears; Approve → moves to Active Agents; Revoke works
5. **Missions tab**: run `scripts/ps-demo.sh` → missions appear; click row → detail modal; Terminate works
6. **Token Requests tab**: trigger a consent flow → item appears; click Consent link → `consent.html` opens; approve/deny works; item clears
7. Verify `GET /.well-known/jwks.json` returns real AS keys (non-empty)
8. Verify `GET /.well-known/aauth-person.json` and `GET /.well-known/aauth-agent.json` both return valid metadata
9. Run `pytest` → all existing smoke tests pass (standalone PS unaffected)
10. Verify standalone PS still starts independently on a different port: `uvicorn ps.http.app:app --port 8766`
