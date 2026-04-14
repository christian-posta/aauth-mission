# AAuth Mission Manager (reference)

Python interfaces and a **FastAPI** server implementing Person Server–style endpoints from **SPEC.md** (missions, token, permission, audit, interaction, consent).

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

**Person Server metadata** (includes `permission_endpoint`, `audit_endpoint`, `token_endpoint`, `mission_endpoint`, and the other URLs from **SPEC**). Use the same host and port as **`AAUTH_MM_PUBLIC_ORIGIN`** so the JSON matches how you call the API.

```bash
curl -sS http://127.0.0.1:8000/.well-known/aauth-person.json | jq
```

```bash
./scripts/mm-demo.sh
# or: BASE_URL=http://127.0.0.1:8080 AGENT_ID=my-agent ./scripts/mm-demo.sh
```

The script prints each HTTP request then the full `curl -i` response. It covers:

- `GET /.well-known/aauth-person.json`
- `POST /mission` with `description` + optional `tools`
- `POST /permission` and `POST /audit` with a `mission` object
- `POST /token` with `AAuth-Mission` header (mission context)
- `GET /consent` + `POST /consent/{pending_id}/decision` (user consent)
- Polling `GET /pending/...` and a `DELETE` → `410` demo

Install **`jq`** for prettier JSON in the script output (`brew install jq`).

### HWK sample client (`scripts/hwk-mm-client.sh`)

`./scripts/mm-demo.sh` uses **`X-AAuth-Agent-Id`** (dev stub). For **real HWK** signing (`AAUTH_MM_INSECURE_DEV=false`), use **`scripts/hwk-mm-client.sh`**, which calls **`aauth.sign_request(..., sig_scheme="hwk")`**, persists an **Ed25519** key as PEM, and signs **`POST /mission`**, **`POST /token`** (optionally embedding `mission` in the JSON body), **`POST /permission`**, **`POST /audit`**, and **`POST /interaction`** (completion).

```bash
AAUTH_MM_INSECURE_DEV=false uvicorn mm.http.app:app --host 127.0.0.1 --port 8000
./scripts/hwk-mm-client.sh --base-url http://127.0.0.1:8000 \
  --mission-description "# Demo\n\nDo something." \
  --permission-action WebSearch --audit
```

Use **`--complete-mission`** to send a `completion` interaction after the token is issued (requires `--mission-description`).

### With plain venv + pip

```bash
cd /path/to/aauth-mission
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
uvicorn mm.http.app:app --reload --host 0.0.0.0 --port 8000
```

### Web console (`/ui`)

Static UI (Alpine.js + Tailwind via CDN) for trying flows in a browser.

- **URL:** `{PUBLIC_ORIGIN}/ui/` (e.g. [http://localhost:8000/ui/](http://localhost:8000/ui/)). Set **`AAUTH_MM_PUBLIC_ORIGIN`** to match the browser origin.
- **Dashboards:** **`user.html`** (legal user: **`/user/missions`**, consent queue) vs **`admin.html`** ( **`GET/PATCH /missions`**, **`GET /admin/pending`**). Mission **PATCH** only supports **`{"state":"terminated"}`** (from **active**). Mission detail includes a **`log`** array.
- **Legal user scoping:** missions must include **`owner_hint`** on **`POST /mission`** equal to **`AAUTH_MM_USER_ID`** if they should appear under “My missions” and in **`GET /user/consent`** for that person.
- **Consent page:** **`/ui/consent.html?code=...`** loads **`GET /consent?code=...`** and posts to **`POST /consent/{pending_id}/decision`**. You normally open it from a link in the **`AAuth-Requirement`** header or queue—no token required on that page for this reference server. Legacy **`/interaction`** routes still work as aliases.

#### What `ADMIN_TOKEN` and `USER_TOKEN` are

They are **shared secrets** the server compares to the **`Authorization: Bearer …`** header. They are **not** issued by an external IdP in this reference app—pick any string you like in env and paste the same value in the UI (or in `curl`).

| Env var | API it gates | Purpose |
|---------|----------------|--------|
| **`AAUTH_MM_USER_TOKEN`** | **`GET/PATCH /user/missions`**, **`GET /user/consent`** | When set, legal-user routes require a matching Bearer token. When **unset**, those routes return **503** (“not configured”). |
| **`AAUTH_MM_ADMIN_TOKEN`** | **`GET/PATCH /missions`**, **`GET /admin/pending`** | When **unset** (default), admin routes are **open** (no Bearer required). When **set**, callers must send **`Authorization: Bearer <that value>`**. |
| **`AAUTH_MM_USER_ID`** | *(with user token)* | Subject id returned for a valid user Bearer token; must match **`owner_hint`** on missions you want that user to own. |

#### How sign-in on `/ui/` works

The login form (`/ui/` → `index.html`) does **not** ask “admin or user?” explicitly. It **probes** the API:

1. **`GET /user/missions`** — if you pasted a token, it sends **`Authorization: Bearer <token>`**; if the field is empty, no Bearer header is sent.
2. If the response is **200** → you are signed in as **legal user** and redirected to **`user.html`**.
3. If the response is **503**, **401**, or **403** → it tries **`GET /missions`** with the **same** headers.
4. If that response is **200** → you are signed in as **admin** and redirected to **`admin.html`**.

Implications:

- **Legal user:** you **must** set **`AAUTH_MM_USER_TOKEN`** and paste **exactly** that secret. An empty token will not succeed as user (you will get **503** if user is unset, or **401/403** if the token is wrong).
- **Admin with no `ADMIN_TOKEN`:** **`GET /missions`** succeeds **without** a Bearer header, so you can leave the token field **empty** and click **Sign in**—you still land on the admin dashboard (handy for local demos).
- **Admin with `ADMIN_TOKEN` set:** paste that same secret so the probe sends the correct Bearer header.

#### Example: run the server with user + optional admin secret

```bash
export AAUTH_MM_USER_TOKEN=dev-user-secret
export AAUTH_MM_USER_ID=alice
# Optional — if set, the UI (and curl) must send this Bearer for /missions and /admin/pending:
# export AAUTH_MM_ADMIN_TOKEN=dev-admin-secret

uvicorn mm.http.app:app --reload --host 0.0.0.0 --port 8000
```

Then open **`/ui/`**: use **`dev-user-secret`** for the legal-user dashboard, or leave the token blank for **open** admin (if **`AAUTH_MM_ADMIN_TOKEN`** is unset), or use **`dev-admin-secret`** if you enabled admin token above.

### Environment (`AAUTH_MM_*`)

| Variable | Default | Meaning |
|----------|---------|---------|
| `PUBLIC_ORIGIN` | `http://localhost:8000` | Public base URL (metadata, **`AAuth-Requirement`** `url=...`). |
| `INSECURE_DEV` | `true` | If `true`, agent routes accept **`X-AAuth-Agent-Id`** without HTTP message signatures. |
| `ADMIN_TOKEN` | *(unset)* | If set, `GET/PATCH /missions` require `Authorization: Bearer <token>`. |
| `USER_TOKEN` | *(unset)* | Enables `/user/missions`, `/user/consent`; requires bearer token. |
| `USER_ID` | `user` | Subject for legal-user token; must match **`owner_hint`** on missions. |
| `AUTO_APPROVE_TOKEN` | `false` | If `true`, **`POST /token`** returns an auth token immediately (no consent). |
| `AUTO_APPROVE_MISSION` | `true` | If `false`, **`POST /mission`** returns **`202`** until the user approves via consent. |
| `PENDING_TTL_SECONDS` | `600` | TTL for open pending rows. |
| `AGENT_JWT_STUB` | `stub-agent-jwt` | Placeholder agent JWT for the federator stub. |
| `JWKS_URI` | *(unset)* | Override **`jwks_uri`** in well-known metadata. |

**Agent identity (dev):** with `INSECURE_DEV=true`, send **`X-AAuth-Agent-Id`** on agent routes.

**Agent identity (production):** `INSECURE_DEV=false` — HTTP Message Signatures (RFC 9421) with **`Signature-Input`**, **`Signature`**, **`Signature-Key`** (`hwk`). The agent id is the JWK thumbprint.

## API overview (SPEC-aligned)

| Endpoint | Purpose |
|----------|---------|
| **`GET /.well-known/aauth-person.json`** | PS metadata: **`issuer`**, **`token_endpoint`**, **`mission_endpoint`**, **`permission_endpoint`**, **`audit_endpoint`**, **`interaction_endpoint`**, **`mission_control_endpoint`**, **`jwks_uri`**. |
| **`POST /mission`** | Proposal: **`{"description":"...","tools":[{"name","description"}], "owner_hint":?}`**. Response: **mission blob JSON** + **`AAuth-Mission`** header (**`s256`** is only in the header, not in the JSON body). |
| **`POST /token`** | **`resource_token`**, optional **`mission`** `{approver,s256}` or **`AAuth-Mission`** request header. |
| **`POST /permission`** | **`action`**, optional **`mission`**, optional **`description`** / **`parameters`**. Returns **`{"permission":"granted"}`** or **`denied`**. |
| **`POST /audit`** | **`mission`** (required), **`action`**, … → **`201 Created`**. |
| **`POST /interaction`** | Agent-facing: **`type`**: `interaction` \| `payment` \| `question` \| `completion`**, optional **`mission`**. Returns **`202`** + poll **`Location`** when user interaction is needed. |
| **`GET /consent?code=`** | User consent context (replaces legacy **`GET /interaction`**). |
| **`POST /consent/{pending_id}/decision`** | User decision; optional **`answer_text`** for **`question`** interactions. |
| **`GET/PATCH /missions`**, **`/user/missions`** | List/detail; **PATCH** only **`state":"terminated"`** from **active**. |

### Mission lifecycle

Missions are **`active`** or **`terminated`**. Termination via **`PATCH`** or by accepting a **`completion`** interaction. Inactive missions yield **`403`** with **`error":"mission_terminated"`** when referenced.

### End-to-end: token + consent

1. **`POST /mission`** (optional) — read **`s256`** from the **`AAuth-Mission`** response header.
2. **`POST /token`** with **`AAuth-Mission`** and/or JSON **`mission`** if operating in mission context.
3. On **`202`**, complete consent in the browser (**`/ui/consent.html?code=...`**). For a non-interactive client, use **`GET /consent?code=...`** then **`POST /consent/{pending_id}/decision`** instead.
4. **`GET`** the **`Location`** pending URL until **`200`** with **`auth_token`**.

### Example: mission + token (dev stub)

This **`curl`** pattern only works when **agent stub mode** is on: **`AAUTH_MM_INSECURE_DEV=true`** (the default) so the server accepts **`X-AAuth-Agent-Id`** instead of HTTP message signatures.

If you see **`401`** with **`invalid_signature`** / “Missing HTTP signature headers”, your process was started with **`AAUTH_MM_INSECURE_DEV=false`**. Either start uvicorn with insecure dev enabled (e.g. `AAUTH_MM_INSECURE_DEV=true uvicorn …`) or use **`scripts/hwk-mm-client.sh`** / **`scripts/hwk_mm_client.py`**, which sign **`POST /mission`** and **`POST /token`** with HWK.

**Copy-paste:** Run the block **from `MM_ORIGIN=` through the closing `fi`** in one shot (including the mission + token requests so **`T`** is set). Pasting only the `TOK_STATUS` / `if` section leaves **`T`** unset. Plain-text copy from this file; some apps turn `"` into curly quotes and cause parse errors (often near **`then`**). Saving the snippet to a file and running **`zsh ./snippet.sh`** avoids interactive paste issues.

```bash
MM_ORIGIN=http://localhost:8000
AGENT_ID=my-agent

R=$(curl -sS -i -X POST "${MM_ORIGIN}/mission" \
  -H 'Content-Type: application/json' \
  -H "X-AAuth-Agent-Id: ${AGENT_ID}" \
  -d '{"description":"# Demo\n\nWork.","owner_hint":"alice","tools":[{"name":"WebSearch","description":"Search"}]}')
echo "$R"
S256=$(printf '%s' "$R" | tr -d '\r' | sed -n 's/.*s256="\([^"]*\)".*/\1/p')
APP=$(printf '%s' "$R" | tr -d '\r' | sed -n 's/.*approver="\([^"]*\)".*/\1/p')

T=$(curl -sS -i -X POST "${MM_ORIGIN}/token" \
  -H 'Content-Type: application/json' \
  -H "X-AAuth-Agent-Id: ${AGENT_ID}" \
  -H "AAuth-Mission: approver=\"$APP\"; s256=\"$S256\"" \
  -d '{"resource_token":"fake-resource-jwt"}')
echo "$T"

# POST /token: **200** → body already has auth_token (no poll). **202** → poll Location (below).
# Status line is like: HTTP/1.1 202 Accepted
TOK_STATUS=$(printf '%s' "$T" | head -1 | tr -d '\r' | awk '{print $2}')
if [[ "$TOK_STATUS" == "202" ]]; then
  LOC_PATH=$(printf '%s' "$T" | tr -d '\r' | grep -i '^Location:' | head -1 | awk '{print $2}' | tr -d '\r')
  HDR=$(printf '%s' "$T" | tr -d '\r' | grep -i '^AAuth-Requirement:' | head -1)
  IX_CODE=$(printf '%s' "$HDR" | grep -o 'code="[^"]*"' | head -1 | cut -d'"' -f2)
  PENDING_URL="${MM_ORIGIN}${LOC_PATH}"

  echo "Open in a browser and approve (or deny) - the page handles consent with the server:"
  echo "  ${MM_ORIGIN}/ui/consent.html?code=${IX_CODE}"
  echo "The loop below keeps polling until that succeeds (expect HTTP 202 on GET /pending while waiting)."

  # Poll the pending URL until 200 (auth_token) or a terminal status:
  while true; do
    POLL=$(curl -sS -i -H "X-AAuth-Agent-Id: ${AGENT_ID}" "$PENDING_URL")
    SC=$(printf '%s' "$POLL" | head -1 | tr -d '\r' | awk '{print $2}')
    BODY=$(printf '%s' "$POLL" | sed '1,/^\r*$/d')
    echo "Poll: HTTP $SC"
    case $SC in
      200|403|410|404) echo "$BODY"; break ;;
    esac
    sleep 2
  done
fi
```

For **API-driven** consent (**`GET /consent?code=...`** then **`POST /consent/{id}/decision`**) without the browser, see **`./scripts/mm-demo.sh`**.

With **`AAUTH_MM_AUTO_APPROVE_TOKEN=true`**, **`POST /token`** returns **`200`** immediately and you can skip polling.

Interactive docs: **`/docs`**, **`/redoc`**.
