# AAuth Mission Manager (reference)

Python interfaces and a small **FastAPI** server that implements the Mission Manager REST surface described in `.cursor/plans/mm_python_interface_design_db08da56.plan.md`, aligned with `.cursor/plans/draft-hardt-aauth-protocol.md`.

## Run the API

### With uv (recommended)

```bash
cd /path/to/aauth-mission
uv venv .venv
uv pip install --python .venv/bin/python -e ".[dev]"
source .venv/bin/activate   # Windows: .venv\Scripts\activate
uvicorn mm.http.app:app --reload --host 0.0.0.0 --port 8000
pytest
```

### Curl walkthrough (manual server)

With the server running on port 8000:

```bash
./scripts/mm-demo.sh
# or: BASE_URL=http://127.0.0.1:8080 AGENT_ID=my-agent ./scripts/mm-demo.sh
```

The script prints each HTTP request (method, URL, headers, JSON body) then the full `curl -i` response (status, response headers, body). It runs the consent flow and a DELETE→410 demo. Install **`jq`** for indented request bodies (`brew install jq`).

### HWK sample client (`scripts/hwk-mm-client.sh`)

`./scripts/mm-demo.sh` uses **`X-AAuth-Agent-Id`** (dev stub). For **real HWK** signing (`AAUTH_MM_INSECURE_DEV=false`), use the Python-backed wrapper **`scripts/hwk-mm-client.sh`**, which calls **`aauth.sign_request(..., sig_scheme="hwk")`**, persists a reusable **Ed25519** key as PEM, **`POST /token`**, then **`GET` polls** the `Location` pending URL with matching signatures.

1. Start the MM with agent signature verification enabled:

   ```bash
   AAUTH_MM_INSECURE_DEV=false uvicorn mm.http.app:app --host 127.0.0.1 --port 8000
   ```

2. In another terminal (once: `chmod +x scripts/hwk-mm-client.sh`):

   ```bash
   ./scripts/hwk-mm-client.sh
   # or, e.g.:
   ./scripts/hwk-mm-client.sh --base-url http://127.0.0.1:8000 --resource-token 'your-resource-jwt'
   ```

   - **Default key file:** `scripts/.hwk-mm-client-key.pem` (created on first run; listed in `.gitignore`). Override with **`--key-file /path/to/key.pem`**.
   - **Base URL:** defaults to **`http://127.0.0.1:8000`**; you can set **`AAUTH_MM_BASE_URL`** instead of **`--base-url`**.
   - If **`POST /token`** returns **`202`**, the client prints a **consent** URL (`/ui/consent.html?code=...`) and polls until the token is ready, the request is **declined** (**`403`** with `denied` / `abandoned`), or another error stops the run.
   - On success (**`200`**), it prints **`expires_in`** and decodes **JWT payload** (unverified) when `auth_token` is a standard three-segment JWT; otherwise it prints the raw **`auth_token`** string (the in-memory federator stub often returns non-JWT placeholders).

The implementation is **`scripts/hwk_mm_client.py`** if you want to run it with **`python scripts/hwk_mm_client.py ...`** directly.

### With plain venv + pip

```bash
cd /path/to/aauth-mission
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
uvicorn mm.http.app:app --reload --host 0.0.0.0 --port 8000
```

### Web console (`/ui`)

The repo ships a small browser UI (HTML + Alpine.js + Tailwind via CDN) for trying the flow without writing `curl` by hand. It is served from the same process as the API.

- **URL:** `{PUBLIC_ORIGIN}/ui/` (e.g. [http://localhost:8000/ui/](http://localhost:8000/ui/)). Set **`AAUTH_MM_PUBLIC_ORIGIN`** to the same origin you use in the browser (`localhost` vs `127.0.0.1` matters for URLs in `AAuth-Requirement`).
- **Sign-in:** paste a **bearer token** on the login page. The UI tries the legal-user API first, then the admin mission-control API (see `mm/http/static/index.html` for the exact order).
- **Admin:** uses `GET/PATCH /missions` and **`GET /admin/pending`** (open deferred flows: token and mission proposals). The admin dashboard lists these under **Open pending requests** with a **Consent** link when an interaction code exists. If `ADMIN_TOKEN` is set, send that bearer token; if unset, mission control and `/admin/pending` are open (same as the API).
- **Legal user:** set `USER_TOKEN` and `USER_ID` (see table below). Missions must include `owner_hint` on `POST /mission` matching `USER_ID`, or they will not appear under “My missions”. Token requests pending consent appear in the consent queue when the MM can associate the agent with an owned mission (same `X-AAuth-Agent-Id` / HWK identity as a mission owned by that user).
- **Consent:** open **Review** from the legal-user queue, or go directly to `/ui/consent.html?code=<code>` using the `code` from `AAuth-Requirement` or `GET /user/consent`.

**Example (one terminal):**

```bash
export AAUTH_MM_USER_TOKEN=dev-user-secret
export AAUTH_MM_USER_ID=alice
export AAUTH_MM_ADMIN_TOKEN=dev-admin-secret   # optional; omit for open admin API
uvicorn mm.http.app:app --reload --host 0.0.0.0 --port 8000
```

Then:

1. Open `/ui/`, sign in with `dev-user-secret` to use the legal-user dashboard (or `dev-admin-secret` for the admin dashboard).
2. In another terminal, create a mission owned by Alice so her UI lists it and token consent can be scoped:

   ```bash
   curl -sS -X POST http://localhost:8000/mission \
     -H 'Content-Type: application/json' \
     -H 'X-AAuth-Agent-Id: my-agent' \
     -d '{"mission_proposal":"# Demo\n\nDo work.","owner_hint":"alice"}'
   ```

   The response includes **`mission.s256`** (hash of the approved mission text). This reference API does **not** pass that id on `POST /token`; instead, the token flow is tied to the mission **by the same agent**: use the identical **`X-AAuth-Agent-Id`** as in this step (`my-agent`). The consent UI (`/ui/consent.html`) loads context via **`GET /interaction?code=...`** in the background.

3. Request a token **for that same agent** (header must match step 2). Then approve in the legal-user **Consent queue** (or open the consent URL below).

   ```bash
   # Same X-AAuth-Agent-Id as POST /mission above — links this token request to mission/consent context.
   curl -sS -i -X POST http://localhost:8000/token \
     -H 'Content-Type: application/json' \
     -H 'X-AAuth-Agent-Id: my-agent' \
     -d '{"resource_token":"fake-resource-jwt"}'
   ```

   Example **full response** (ids and codes vary each run):

   ```http
   HTTP/1.1 202 Accepted
   date: Thu, 09 Apr 2026 22:37:18 GMT
   server: uvicorn
   location: /pending/K1l_fVS827JuSrM9
   retry-after: 0
   cache-control: no-store
   aauth-requirement: requirement=interaction; url="http://localhost:8000/ui/consent.html"; code="oMulzMRtR-fXLOf6qt0F5g"
   content-length: 20
   content-type: application/json

   {"status":"pending"}
   ```

   **Build the consent URL and a `curl` for the interaction JSON** (copy-paste after the `POST /token` above, or run as one block):

   ```bash
   HDR=$(curl -sS -i -X POST http://localhost:8000/token \
     -H 'Content-Type: application/json' \
     -H 'X-AAuth-Agent-Id: my-agent' \
     -d '{"resource_token":"fake-resource-jwt"}')
   printf '%s\n' "$HDR"

   LINE=$(printf '%s\n' "$HDR" | grep -i '^aauth-requirement:')
   BASE=$(printf '%s\n' "$LINE" | sed -E 's/.*url="([^"]+)".*/\1/')
   CODE=$(printf '%s\n' "$LINE" | sed -E 's/.*code="([^"]+)".*/\1/')
   ORIGIN="${BASE%/ui/consent.html}"
   CONSENT_URL="${BASE}?code=${CODE}"

   echo ""
   echo "Open in a browser:"
   echo "$CONSENT_URL"
   echo ""
   echo "Or curl the interaction API (JSON context):"
   echo "curl -sS \"${ORIGIN}/interaction?code=${CODE}\""
   ```

   Paste the printed **`curl -sS "http://localhost:8000/interaction?code=..."`** line into the shell to fetch the same payload the consent page uses.

Interactive API docs remain at `/docs` and `/redoc`.

### Environment (`AAUTH_MM_*`)

Each variable below is read with the **`AAUTH_MM_` prefix** (e.g. `AAUTH_MM_ADMIN_TOKEN` for `ADMIN_TOKEN`).

| Variable | Default | Meaning |
|----------|---------|---------|
| `PUBLIC_ORIGIN` | `http://localhost:8000` | Public MM base URL (metadata, **`AAuth-Requirement`** `url=...`). Should match how you open the app in the browser. |
| `INSECURE_DEV` | `true` | If `true`, agent routes do not verify HTTP message signatures; send **`X-AAuth-Agent-Id`** (see below). |
| `ADMIN_TOKEN` | *(unset)* | If set, `GET/PATCH /missions` require `Authorization: Bearer <token>`. |
| `USER_TOKEN` | *(unset)* | If set, enables `GET/PATCH /user/missions` and `GET /user/consent`; require `Authorization: Bearer <token>`. If unset, those routes return `503`. |
| `USER_ID` | `user` | Owner id for the legal-user token; must match `owner_hint` on missions you want to see in `/user/missions`. |
| `AUTO_APPROVE_TOKEN` | `false` | If `true`, `POST /token` skips consent and returns a fake auth token immediately. |
| `AUTO_APPROVE_MISSION` | `true` | If `false`, `POST /mission` returns `202` pending until the user approves via the interaction flow. |
| `PENDING_TTL_SECONDS` | `600` | Time-to-live for open pending rows (expired → `408` / `403 abandoned` if the user had opened consent). |
| `AGENT_JWT_STUB` | `stub-agent-jwt` | Dummy agent JWT passed to the federator stub. |
| `JWKS_URI` | *(unset)* | Override `jwks_uri` in `/.well-known/aauth-mission.json`. |

**Agent identity (dev):** with `INSECURE_DEV=true`, send header **`X-AAuth-Agent-Id`** (any string) on `POST /mission`, `POST /token`, `GET/POST/DELETE /pending/...`.

**Agent identity (production):** set `INSECURE_DEV=false`. Agent requests must include **HTTP Message Signatures** (RFC 9421) with **`Signature-Input`**, **`Signature`**, and **`Signature-Key`** using scheme **`hwk`** (public key in `Signature-Key`). The server uses the **`aauth`** library to verify signatures; the agent identifier is the **JWK thumbprint** of that key (pseudonymous). Admin and legal-user routes continue to use **`Authorization: Bearer`** only.

## Flow (in-memory)

Yes: this implementation supports **`POST /token` → `202`**, human consent, and the agent **`GET /pending/{pending_id}`** poll on the **`Location`** URL until the token is ready.

The **`AAuth-Requirement`** header advertises **`url="<PUBLIC_ORIGIN>/ui/consent.html"`** and a separate **`code="..."`**. Open **`/ui/consent.html?code=...`** in a browser (or build that URL from the header). That page calls **`GET /interaction?code=...`** (JSON) and **`POST /interaction/{pending_id}/decision`** to complete the flow. API-only clients can still call those `/interaction` routes directly without the HTML shell.

### End-to-end sequence

1. **Agent — request token** → `202 Accepted`  
   Response includes:
   - **`Location`**: absolute or relative URL of the pending resource, e.g. `/pending/<pending_id>` (poll this).
   - **`AAuth-Requirement`**: includes `requirement=interaction`, `url="<PUBLIC_ORIGIN>/ui/consent.html"` (browser entry point), and `code="<one-time code>"` (append as `?code=` to that URL).
   - **`Retry-After`**: seconds the agent should wait before the next poll (the in-memory stub often uses `0`).
   - Body: `{"status":"pending"}` (and optional fields per deferred response).

2. **Human — consent (browser or curl)**  
   - **Browser:** open **`/ui/consent.html?code=<code>`** (same host as `PUBLIC_ORIGIN`).  
   - **API / curl:** `GET /interaction?code=<code>` — returns JSON context (and marks the pending row as `interacting`).  
   - `POST /interaction/{pending_id}/decision` with `{"approved": true}` or `{"approved": false}` — completes or denies (the HTML page does this for you).

3. **Agent — poll until ready**  
   - `GET` the same URL as **`Location`** (i.e. `GET /pending/{pending_id}`) using the **same agent credentials** as `POST /token` (with `INSECURE_DEV=true`, header **`X-AAuth-Agent-Id`**; with `INSECURE_DEV=false`, the same HWK signature headers). Poll as `Retry-After` suggests.  
   - While consent is outstanding → **`202`** with the same pending semantics.  
   - After approval → **`200`** once with `{"auth_token","expires_in"}`; a **second** `GET` on the same pending URL returns **`404`** (terminal response is single-use).  
   - If the pending was cancelled → **`410`**; if denied → **`403`** (JSON body uses `error` / `error_description` per the protocol).

### Example: consent with curl, then poll

Assume the server is at `http://localhost:8000` (match **`AAUTH_MM_PUBLIC_ORIGIN`**) and `INSECURE_DEV=true`.

**Step A — agent starts the token request (save headers):**

```bash
curl -sS -i -X POST http://localhost:8000/token \
  -H 'Content-Type: application/json' \
  -H 'X-AAuth-Agent-Id: my-agent' \
  -d '{"resource_token":"fake-resource-jwt"}'
```

From the response, read **`Location`** (e.g. `/pending/abc123`) and parse **`code`** from the **`AAuth-Requirement`** header, e.g. `code="nM0..."`.

**Step B — human approves (use the `code` from the header, and `pending_id` from `Location` or from `GET /interaction`):**

```bash
# Optional: inspect context (also transitions to "interacting")
curl -sS "http://localhost:8000/interaction?code=PASTE_CODE_HERE"

# Approve (replace PENDING_ID)
curl -sS -X POST "http://localhost:8000/interaction/PENDING_ID/decision" \
  -H 'Content-Type: application/json' \
  -d '{"approved": true}'
```

**Step C — agent polls `Location` until `200`:**

```bash
LOC="http://localhost:8000/pending/PENDING_ID"   # use the exact Location from step A

while true; do
  R=$(curl -sS -w "\n%{http_code}" -o /tmp/mm-poll.json -H 'X-AAuth-Agent-Id: my-agent' "$LOC")
  CODE=$(echo "$R" | tail -n1)
  if [ "$CODE" = "200" ]; then
    cat /tmp/mm-poll.json
    break
  fi
  if [ "$CODE" = "403" ] || [ "$CODE" = "410" ]; then
    echo "failed: HTTP $CODE"; cat /tmp/mm-poll.json; break
  fi
  # Optional: parse Retry-After from previous 202; this stub often returns 0
  sleep 1
done
```

You should see JSON with **`auth_token`** and **`expires_in`** when the loop exits with `200`.

Mission creation: `POST /mission` with JSON `{"mission_proposal": "# ...markdown...", "owner_hint": "<optional legal owner id>"}` returns `200` and `{"mission":{"s256","approved"}}`. Omit `owner_hint` if only admins should see the mission via `/missions` (not scoped to a legal user).

Metadata: `GET /.well-known/aauth-mission.json`.
