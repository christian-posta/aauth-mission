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

### With plain venv + pip

```bash
cd /path/to/aauth-mission
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
uvicorn mm.http.app:app --reload --host 0.0.0.0 --port 8000
```

### Environment (`AAUTH_MM_*`)

| Variable | Default | Meaning |
|----------|---------|---------|
| `PUBLIC_ORIGIN` | `http://127.0.0.1:8000` | Public MM base URL (metadata, interaction `url` in `AAuth-Requirement`). |
| `INSECURE_DEV` | `true` | If `true`, agent routes do not verify HTTP message signatures; send **`X-AAuth-Agent-Id`** (see below). |
| `ADMIN_TOKEN` | *(unset)* | If set, `GET/PATCH /missions` require `Authorization: Bearer <token>`. |
| `AUTO_APPROVE_TOKEN` | `false` | If `true`, `POST /token` skips consent and returns a fake auth token immediately. |
| `AGENT_JWT_STUB` | `stub-agent-jwt` | Dummy agent JWT passed to the federator stub. |
| `JWKS_URI` | *(unset)* | Override `jwks_uri` in `/.well-known/aauth-mission.json`. |

**Agent identity (dev):** with `INSECURE_DEV=true`, send header **`X-AAuth-Agent-Id`** (any string) on `POST /mission`, `POST /token`, `POST/DELETE /pending/...`.

Production deployments should set `INSECURE_DEV=false` and plug in real HTTP message signature + agent JWT verification (not included here).

## Flow (in-memory)

1. `POST /token` with `X-AAuth-Agent-Id` → `202` + `Location` + `AAuth-Requirement: requirement=interaction; url=...; code=...` and body `{"status":"pending"}`.
2. Open `GET /interaction?code=<code>` (optional for humans; sets status to `interacting`).
3. `POST /interaction/{pending_id}/decision` with `{"approved": true}`.
4. `GET /pending/{pending_id}` → `200` with `auth_token` / `expires_in` (from `FakeASFederator`).

Mission creation: `POST /mission` with JSON `{"mission_proposal": "# ...markdown..."}` returns `200` and `{"mission":{"s256","approved"}}`.

Metadata: `GET /.well-known/aauth-mission.json`.
