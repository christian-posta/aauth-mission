# AAuth Agent Server Implementation Plan

## Context

This plan describes how to implement an AAuth Agent Server supporting **Path B: Direct Registration + Stable Key Renewal** for desktop/laptop agents. No PS involvement, no bootstrap_token.

**Framing:** The agent server is the trust anchor for a **person's own agents**. The person who approves registrations is the same person this server represents — not an external admin. Agents are the person's agents, running on the person's devices. The approval UI is a first-class part of the person's experience.

**The flow in plain English:**
1. Agent generates a stable key pair (lives in OS Keychain forever) and an ephemeral key pair (lives for ≤24h)
2. Agent sends a self-registration request to the agent server with its stable and ephemeral public keys
3. Agent server queues the request as pending and returns a 202 — the person's approval required
4. The person (laptop owner) approves the registration via a UI or API endpoint
5. Agent server creates a binding (`agent_id ↔ stable_pub`) and issues an agent token bound to the ephemeral key
6. When the agent token expires, the agent silently renews it using the stable key (`jkt-jwt`) — no person involved

The agent token contains no `ps` claim. The agent operates in identity-based (2-party) mode against resources.

---

## Architecture Overview

```
                                         Agent Server
                                    +-----------------------+
                                    |                       |
  Agent ---- POST /register ------->| Registration Handler  |
         (stable_pub + eph_pub)     |   - verify HTTP sig   |
                                    |   - queue pending reg |
                                    |   - return 202        |
                                    |                       |
  Agent ---- GET /pending/{id} ---->| Pending Poll          |
                                    |   - approved? issue   |
                                    |     agent token       |
                                    |   - denied? 403       |
                                    |   - pending? 202      |
                                    |                       |
  Person --- GET /person/           | Person Approval UI    |
             registrations          |   - list pending regs |
             POST /person/          |   - approve/deny      |
             registrations/{id}/    |   - link to binding   |
             approve|deny|link      |                       |
                                    |                       |
  Agent ---- POST /refresh -------->| Refresh Handler       |
         (jkt-jwt, new eph_pub)     |   - verify HTTP sig   |
                                    |   - lookup binding    |
                                    |     by stable key JKT |
                                    |   - issue new token   |
                                    |                       |
  Anyone --- GET /.well-known/ ---->| Metadata + JWKS       |
              aauth-agent.json      |                       |
              jwks.json             |                       |
                                    +-----------------------+
                                    |                       |
                                    |  Internal Stores:     |
                                    |   - Bindings          |
                                    |   - Pending Regs      |
                                    |   - JTI Replay Cache  |
                                    |   - Server Signing Key|
                                    +-----------------------+
```

---

## Part 1: Data Model

### 1.1 PendingRegistration

Created when an agent registers itself. Waits for the person's approval.

```python
@dataclass
class PendingRegistration:
    id: str                     # opaque random ID, used in pending URL
    stable_pub: dict            # JWK of the agent's stable public key
    ephemeral_pub: dict         # JWK of the agent's ephemeral public key
    label: str | None           # human-readable name the agent supplied (e.g. "MacBook Pro - Claude")
    stable_jkt: str             # urn:jkt:sha-256:<thumbprint> of stable_pub, for dedup
    created_at: datetime
    expires_at: datetime        # pending registrations expire if not approved (e.g. 1 hour)
    status: Literal["pending", "approved", "denied"]
```

### 1.2 Binding

Created when a pending registration is approved **by the person**. One per agent identity.

```python
@dataclass
class Binding:
    agent_id: str                       # "aauth:<uuid>@agent-server.example"
    label: str | None                   # human-readable label from registration
    created_at: datetime
    stable_key_thumbprints: list[str]   # urn:jkt:sha-256:<thumbprint>; one per enrolled device
    revoked: bool = False
```

Multiple devices can be associated with the same binding: second laptop enrolls separately, person approves and links the new pending registration to an existing binding, adding its thumbprint.

### 1.3 Agent Token Claims (output structure)

```python
# JWT Header
{
    "alg": "EdDSA",
    "typ": "aa-agent+jwt",
    "kid": "<agent-server-key-id>"
}

# JWT Payload
{
    "iss": "https://agent-server.example",     # Agent server URL
    "dwk": "aauth-agent.json",                 # MUST be this exact string
    "sub": "aauth:<uuid>@agent-server.example",# Stable agent identity
    "jti": "<uuid>",                           # Replay detection + revocation
    "cnf": {
        "jwk": { ... }                         # Agent's EPHEMERAL public key ONLY
    },
    "iat": 1745400000,
    "exp": 1745486400                          # SHOULD NOT exceed 24 hours
    # No "ps" claim — Path B has no Person Server
}
```

The token is signed with the **agent server's own private signing key**. The agent's ephemeral key appears only in `cnf.jwk`. Use `aauth.create_agent_token()` to issue.

---

## Part 2: Endpoints

### 2.1 Well-Known Metadata

**`GET /.well-known/aauth-agent.json`**

```json
{
    "issuer": "https://agent-server.example",
    "jwks_uri": "https://agent-server.example/.well-known/jwks.json",
    "client_name": "My Laptop Agent Server",
    "registration_endpoint": "https://agent-server.example/register",
    "refresh_endpoint": "https://agent-server.example/refresh"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `issuer` | YES | Agent server HTTPS URL. Lowercase, no port/path/trailing slash |
| `jwks_uri` | YES | URL to agent server's own signing JWKS |
| `client_name` | NO | Human-readable name |
| `registration_endpoint` | YES | URL for agent self-registration |
| `refresh_endpoint` | YES | URL for token renewal |
| `callback_endpoint` | NO | HTTPS callback URL |
| `localhost_callback_allowed` | NO | Boolean, default false |

### 2.2 JWKS Endpoint

**`GET /.well-known/jwks.json`**

The agent server's **own** signing public keys — used by resources to verify agent tokens this server issued. Has nothing to do with the agent's keys.

```json
{
    "keys": [
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "as-key-2026-04",
            "x": "<base64url public key>",
            "use": "sig",
            "alg": "EdDSA"
        }
    ]
}
```

**Caching (protocol spec line 2076):**
- Verifiers MUST NOT fetch more than once per minute
- Verifiers SHOULD discard cache after max 24 hours
- Support `Cache-Control` / `Expires` headers
- On unknown `kid`, verifiers refresh cache (key rotation support)

Keep the previous key in the JWKS for at least 24h after rotating.

### 2.3 Registration Endpoint

**`POST /register`**

Agent self-registers. The HTTP request is signed with the ephemeral private key using `hwk`. The stable public key is in the body. Returns 202 — the agent must poll until the person approves.

**Request:**
```http
POST /register HTTP/1.1
Host: agent-server.example
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1745400000
Signature: sig=:<signed with ephemeral private key>:
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="<eph_pub>"
Content-Type: application/json

{
    "stable_pub": {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "<stable_pub base64url>"
    },
    "label": "MacBook Pro - Claude Agent"
}
```

**Agent server on receiving:**
1. Verify the HTTP Message Signature (hwk scheme, ephemeral key inline) using `aauth.verify_signature()`
2. Compute `stable_jkt = urn:jkt:sha-256:<aauth.calculate_jwk_thumbprint(stable_pub)>`
3. Check for existing binding with this `stable_jkt` — if found, issue a new token immediately (agent re-registering a known device). No person approval needed.
4. Otherwise create a `PendingRegistration` record, storing both `stable_pub` and `ephemeral_pub`
5. Return 202 with a `Location` pending URL

**Response:**
```http
HTTP/1.1 202 Accepted
Location: /pending/abc123
Retry-After: 5
Cache-Control: no-store
Content-Type: application/json

{
    "status": "pending"
}
```

**Error responses:**
- `401 Unauthorized` if HTTP signature is invalid

### 2.4 Pending Poll Endpoint

**`GET /pending/{id}`**

Agent polls this until the registration is approved or denied. **The request MUST be signed with the same ephemeral key used at registration** (proves continuity — the same agent is polling).

**Request:**
```http
GET /pending/abc123 HTTP/1.1
Host: agent-server.example
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1745400001
Signature: sig=:<signed with same ephemeral private key>:
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="<eph_pub>"
```

**Agent server on receiving:**
1. Verify HTTP signature (must use `hwk` scheme)
2. Verify the ephemeral public key in `Signature-Key` matches `ephemeral_pub` stored on the `PendingRegistration` for this `id`
3. Dispatch on `status`:
   - `pending`: return 202
   - `denied` or expired: return error
   - `approved`: look up binding created at approval time, issue agent token with `cnf.jwk = ephemeral_pub`, return 200

**Responses:**

Still pending (`202`):
```json
{ "status": "pending" }
```

Approved (`200`) — returns the agent token:
```json
{
    "agent_token": "<JWT>"
}
```

Denied (`403`):
```json
{ "error": "denied" }
```

Expired (`410`):
```json
{ "error": "expired" }
```

### 2.5 Person: List Pending Registrations

**`GET /person/registrations`**

Returns all pending registrations awaiting the person's approval. Requires person authentication (bearer token).

```json
[
    {
        "id": "abc123",
        "label": "MacBook Pro - Claude Agent",
        "stable_jkt": "urn:jkt:sha-256:abc...",
        "created_at": "2026-04-22T10:00:00Z",
        "expires_at": "2026-04-22T11:00:00Z",
        "status": "pending"
    }
]
```

### 2.6 Person: Approve Registration

**`POST /person/registrations/{id}/approve`**

Requires person authentication. **Binding is created here**, at approval time.

On approve:
- Generate `agent_id`: `aauth:<uuid>@<server_domain>`
- Create `Binding` from the `PendingRegistration` (stable_jkt, label, agent_id)
- Mark `PendingRegistration.status = "approved"`
- The next poll from the agent will receive the agent token

Response: `200 OK`
```json
{
    "agent_id": "aauth:550e8400-e29b-41d4-a716-446655440000@agent-server.example",
    "label": "MacBook Pro - Claude Agent"
}
```

### 2.7 Person: Deny Registration

**`POST /person/registrations/{id}/deny`**

Requires person authentication.

- Mark `PendingRegistration.status = "denied"`
- The next poll from the agent will receive a 403

Response: `200 OK`

### 2.8 Person: Link Registration to Existing Binding

**`POST /person/registrations/{id}/link`**

For multi-device enrollment. The person associates a new device's pending registration with an existing agent identity (binding) rather than creating a new one.

Requires person authentication.

**Request body:**
```json
{
    "agent_id": "aauth:550e8400-e29b-41d4-a716-446655440000@agent-server.example"
}
```

On link:
- Verify the pending registration exists and is `status=pending`
- Verify the target binding exists and is not revoked
- Add `stable_jkt` from the pending registration to `binding.stable_key_thumbprints`
- Mark `PendingRegistration.status = "approved"` (same as approve — the poll will issue a token)

Response: `200 OK`
```json
{
    "agent_id": "aauth:550e8400-e29b-41d4-a716-446655440000@agent-server.example",
    "label": "MacBook Pro - Claude Agent (linked)"
}
```

**Error responses:**
- `404` if pending registration or target binding not found
- `409` if `stable_jkt` is already on the binding

### 2.9 Person: List Bindings

**`GET /person/bindings`**

Returns all active agent bindings. Requires person authentication.

```json
[
    {
        "agent_id": "aauth:550e8400-e29b-41d4-a716-446655440000@agent-server.example",
        "label": "My Claude Agent",
        "created_at": "2026-04-22T10:00:00Z",
        "device_count": 2,
        "revoked": false
    }
]
```

### 2.10 Person: Revoke Binding

**`POST /person/bindings/{agent_id}/revoke`**

Requires person authentication. Sets `binding.revoked = True`. All subsequent refresh attempts with any stable key from this binding will fail.

Response: `200 OK`

### 2.11 Refresh Endpoint

**`POST /refresh`**

Token renewal. No person interaction. The agent uses its stable private key to sign a `jkt-jwt` JWT delegating to a new ephemeral key, then signs the HTTP request with the new ephemeral private key.

**The `jkt-jwt` JWT structure** (critical — must match what `aauth.verify_signature()` expects):

```
JWT Header: {
    "alg": "EdDSA",
    "typ": "jkt-s256+jwt",        # MUST be jkt-s256+jwt (SHA-256)
    "jwk": { <stable_pub JWK> }   # Stable public key in JWT header
}
JWT Payload: {
    "iss": "urn:jkt:sha-256:<thumbprint of stable_pub>",
    "cnf": { "jwk": { <new_eph_pub JWK> } },
    "iat": <now>,
    "exp": <now + short ttl>
}
JWT Signature: <signed with stable_priv>
```

**Renewal flow:**
```
Agent                                          Agent Server
  |                                                 |
  | 1. Generate NEW ephemeral key pair              |
  |    new_eph_priv, new_eph_pub                    |
  |                                                 |
  | 2. Build jkt-jwt JWT:                           |
  |    Header: { typ: jkt-s256+jwt,                 |
  |              jwk: stable_pub }                  |
  |    Payload: { iss: urn:jkt:sha-256:<jkt>,       |
  |               cnf: { jwk: new_eph_pub } }       |
  |    Sign with: stable_priv                       |
  |                                                 |
  | 3. POST /refresh (empty body)                   |
  |    HTTP sig: new_eph_priv (hwk or jkt-jwt)      |
  |    Signature-Key: jkt-jwt;jwt="<above JWT>"     |
  |------------------------------------------------>|
  |                                                 |
  |                  4. aauth.verify_signature()    |
  |                     - Extracts stable_pub from  |
  |                       JWT header.jwk            |
  |                     - Computes urn:jkt thumbprint|
  |                     - Verifies JWT sig           |
  |                     - Extracts cnf.jwk from JWT  |
  |                       payload (new_eph_pub)      |
  |                     - Verifies HTTP sig with     |
  |                       new_eph_pub                |
  |                  5. Compute stable JKT           |
  |                  6. Lookup binding by JKT        |
  |                  7. Issue new agent token        |
  |                                                 |
  | { agent_token }                                 |
  |<------------------------------------------------|
```

**Request:**
```http
POST /refresh HTTP/1.1
Host: agent-server.example
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1745400000
Signature: sig=:<signed with NEW ephemeral private key>:
Signature-Key: sig=jkt-jwt;jwt="<JWT signed by stable_priv, cnf.jwk=new_eph_pub>"
```

Body is empty.

**Agent server MUST:**
1. Call `aauth.verify_signature()` — it handles the full `jkt-jwt` chain internally:
   - Extracts `stable_pub` from JWT header `jwk`
   - Computes `urn:jkt:sha-256:<thumbprint>`
   - Verifies JWT signature with `stable_pub`
   - Extracts `cnf.jwk` (new ephemeral key) from JWT payload
   - Verifies HTTP signature with new ephemeral key
2. Extract the stable JKT from the verified result
3. Look up binding by `stable_jkt`; if not found or revoked → 401/404
4. Issue a fresh agent token (same `sub`, new `cnf.jwk = new_eph_pub`) using `aauth.create_agent_token()`

**Error responses:**
- `401 Unauthorized` — bad signature, revoked binding
- `404 Not Found` — binding not found

**Success response:**
```json
{
    "agent_token": "<JWT>"
}
```

### 2.12 Revocation Endpoint (Optional)

**`POST /revoke`**

```http
POST /revoke HTTP/1.1
Host: agent-server.example
Signature-Input: sig=...
Signature: sig=...
Signature-Key: sig=jwt;jwt="<current agent token>"
Content-Type: application/json

{
    "jti": "<token-identifier>"
}
```

`200` if revoked or already invalid. `404` if `jti` not recognized.

---

## Part 3: Core Services

### 3.1 Signing Service

Manages the agent server's own Ed25519 signing keys.

```python
class SigningService:
    def sign_agent_token(self, claims: dict) -> str:
        """Delegates to aauth.create_agent_token(). Injects iss, kid."""

    def get_jwks(self) -> dict:
        """Return JWKS with current + previous signing public keys via aauth.generate_jwks()."""

    def rotate_key(self) -> None:
        """Generate new signing key via aauth.generate_ed25519_keypair(), move current to previous."""
```

Key storage: file-based PEM for reference implementation. Production: HSM or cloud KMS.

On startup: if `signing_key_path` is not set or the file doesn't exist, auto-generate and persist.

### 3.2 HTTP Signature Verification Service

Wraps `aauth.verify_signature()` for use as a FastAPI dependency.

**Verification procedure (protocol spec line 2061) — handled by aauth library:**

1. Extract `Signature`, `Signature-Input`, `Signature-Key`. If missing → `invalid_request`
2. Verify `Signature-Input` covers `@method`, `@authority`, `@path`, `signature-key`. If not → `invalid_input`
3. Verify `created` within 60-second window. If not → `invalid_signature`
4. Determine algorithm from `alg` in key. If unsupported → `unsupported_algorithm`
5. Obtain public key per scheme:
   - `hwk`: inline public key in header
   - `jkt-jwt`: JWT (typ=`jkt-s256+jwt`), `jwk` in header = stable pub, `cnf.jwk` = ephemeral key
6. Verify HTTP Message Signature. If fail → `invalid_signature`

**Replay protection:** Cache `(key_thumbprint, created)` pairs for 60 seconds.

```python
class HttpSigVerifier:
    def verify_request(
        self,
        method: str,
        authority: str,
        path: str,
        headers: dict,
    ) -> VerifiedRequest:
        """Calls aauth.verify_signature(). Returns VerifiedRequest with scheme, public key, stable JKT if jkt-jwt."""
```

### 3.3 Pending Registration Store

```python
class PendingRegistrationStore:
    def create(
        self,
        stable_pub: dict,
        ephemeral_pub: dict,
        label: str | None,
        ttl_seconds: int = 3600,
    ) -> PendingRegistration:

    def get(self, pending_id: str) -> PendingRegistration | None:

    def approve(self, pending_id: str) -> None:
        """Mark as approved. Binding must already be created by caller before calling this."""

    def deny(self, pending_id: str) -> None:

    def list_pending(self) -> list[PendingRegistration]:

    def find_by_stable_jkt(self, stable_jkt: str) -> PendingRegistration | None:
        """Check for duplicate in-flight registrations from the same device."""
```

### 3.4 Binding Store

```python
class BindingStore:
    def create(self, agent_id: str, label: str | None, stable_jkt: str) -> Binding:

    def lookup_by_stable_jkt(self, jkt: str) -> Binding | None:
        """Find binding by urn:jkt:sha-256:<thumbprint>."""

    def get_by_agent_id(self, agent_id: str) -> Binding | None:

    def list_all(self) -> list[Binding]:

    def add_stable_key(self, agent_id: str, stable_jkt: str) -> None:
        """Add another device's stable key to an existing binding (link flow)."""

    def revoke(self, agent_id: str) -> None:
```

### 3.5 Agent Token Factory

Thin wrapper around `aauth.create_agent_token()`.

```python
class AgentTokenFactory:
    def issue(
        self,
        agent_id: str,
        ephemeral_pub_key: dict,
        lifetime_seconds: int = 86400,
    ) -> str:
        """Calls aauth.create_agent_token(iss, sub=agent_id, cnf_jwk=ephemeral_pub_key, ...)."""
```

Token structure:
```
Header: { alg: EdDSA, typ: aa-agent+jwt, kid: <server-key-id> }
Payload: { iss, dwk: "aauth-agent.json", sub, jti: <uuid>, cnf: { jwk: <eph_pub> }, iat, exp }
Signature: <signed with agent server's private key>
```

---

## Part 4: Signature Scheme Summary

| Context | Scheme | Signing key | What it proves |
|---------|--------|-------------|----------------|
| Agent → `/register` | `hwk` | eph_priv (inline) | Agent holds eph_priv |
| Agent → `/pending/{id}` | `hwk` | eph_priv (inline, same key as registration) | Same agent is polling |
| Agent → Resource (post-registration) | `jwt` | eph_priv | Agent holds eph_priv; agent token binds it to identity |
| Agent → `/refresh` | `jkt-jwt` | stable_priv signs JWT; eph_priv signs HTTP | Agent holds stable_priv (registered at approval) and new eph_priv |

### How `jkt-jwt` works for renewal

Two keys, two signatures:

1. **stable_priv** signs a `jkt-s256+jwt`:
   ```
   Header: { alg: EdDSA, typ: jkt-s256+jwt, jwk: <stable_pub> }
   Payload: { iss: "urn:jkt:sha-256:<thumbprint>", cnf: { jwk: <new_eph_pub> }, iat, exp }
   ```
   This says: "I (stable_priv holder) delegate to this new ephemeral key."

2. **new_eph_priv** signs the HTTP request, with the above JWT in `Signature-Key`.

The `aauth.verify_signature()` library call handles the full chain:
- Extracts `stable_pub` from JWT header `jwk`
- Computes thumbprint and matches against JWT payload `iss`
- Verifies JWT signature → proves stable key possession
- Extracts `cnf.jwk` from JWT payload → the new ephemeral key
- Verifies HTTP signature with new ephemeral key → proves new ephemeral key possession

---

## Part 5: Project Structure

```
agent_server/
    __init__.py
    models.py                       # PendingRegistration, Binding, VerifiedRequest, etc.
    exceptions.py                   # BindingNotFound, InvalidSignature, PendingExpired, etc.
    api/
        __init__.py
        registration_routes.py      # POST /register, GET /pending/{id}
        refresh_routes.py           # POST /refresh
        person_routes.py            # GET/POST /person/registrations/..., /person/bindings/...
        metadata.py                 # GET /.well-known/aauth-agent.json + jwks.json
    service/
        __init__.py
        signing.py                  # SigningService (server key management + JWT signing)
        http_sig.py                 # HttpSigVerifier (wraps aauth.verify_signature())
        token_factory.py            # AgentTokenFactory (wraps aauth.create_agent_token())
    impl/
        __init__.py
        memory_registrations.py     # In-memory PendingRegistrationStore
        memory_bindings.py          # In-memory BindingStore
        memory_replay.py            # In-memory replay cache (thumbprint + created)
    http/
        __init__.py
        app.py                      # FastAPI application
        config.py                   # AgentServerSettings (pydantic-settings)
        deps.py                     # Dependency injection
    utils/
        __init__.py
        agent_id.py                 # Agent identifier generation + validation
```

### Dependencies (pyproject.toml additions)

```toml
# In the shared aauth-person-server pyproject.toml, add:
"aauth==0.3.2",          # Provides: verify_signature(), create_agent_token(),
                          #   calculate_jwk_thumbprint(), generate_ed25519_keypair(),
                          #   public_key_to_jwk(), jwk_to_public_key(), generate_jwks()
                          #   Full jkt-jwt scheme support built in.
"PyJWT>=2.8.0",          # JWT header parsing (supplemental to aauth)
"cryptography>=42.0.0",  # Ed25519 key serialization to/from PEM files
```

**No `httpx` needed** — Path B has no outbound JWKS fetching.

**Key aauth 0.3.2 functions used:**
- `aauth.verify_signature()` — verifies `hwk` and `jkt-jwt` schemes (full RFC 9421)
- `aauth.create_agent_token()` — issues `aa-agent+jwt` with all required claims
- `aauth.calculate_jwk_thumbprint()` — RFC 7638 thumbprint for `urn:jkt:sha-256:...`
- `aauth.generate_ed25519_keypair()` — key generation
- `aauth.public_key_to_jwk()` / `aauth.jwk_to_public_key()` — key conversion
- `aauth.generate_jwks()` — JWKS document construction

### Configuration

```python
class AgentServerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AAUTH_AS_")

    issuer: str = "https://agent-server.example"
    server_domain: str = "agent-server.example"
    public_origin: str = "http://localhost:8800"

    signing_key_path: str | None = None         # Ed25519 PEM; auto-generated if None
    previous_key_path: str | None = None        # Previous key for JWKS rotation

    agent_token_lifetime: int = 86400           # Max 24h per spec
    registration_ttl: int = 3600                # 1 hour for pending registrations
    signature_window: int = 60                  # 60 seconds per spec

    client_name: str = "AAuth Agent Server"

    person_token: str = "changeme"              # Bearer token for /person/* endpoints
    insecure_dev: bool = False                  # Skip signature verification in dev
```

**Startup warning:** If `person_token == "changeme"` and `insecure_dev == False`, log a warning at startup:
```
WARNING: AAUTH_AS_PERSON_TOKEN is set to the default value. Change it before exposing this server.
```

---

## Part 6: UI

The agent server UI is a first-class part of the person's experience. It is mounted at `/ui` on the agent server (same pattern as the person server's `/ui` static mount). The styling and interaction patterns follow the existing person server UI.

### 6.1 Pages

**`/ui/index.html` — Dashboard**
- Summary: number of pending registrations, number of active bindings
- Quick links to Pending Registrations and My Agents
- Shows server identity (`issuer`, `client_name`)

**`/ui/registrations.html` — Pending Registrations**

The main approval UX. The person lands here to handle new device enrollments.

Layout:
- Table or card list of pending registrations
- Each row shows: `label`, `stable_jkt` (truncated, copyable), time since request, expiry countdown
- Per-row actions:
  - **Approve** — creates a new binding
  - **Deny** — rejects the registration
  - **Link to existing agent** — opens a modal/dropdown showing existing bindings to merge into
- Empty state: "No pending registrations."
- Auto-refreshes every 5 seconds while items are pending

**`/ui/agents.html` — My Agents**

Shows the person's approved agent bindings.

Layout:
- Card or table per binding
- Each shows: `label`, `agent_id` (copyable), creation date, number of enrolled devices (`stable_key_thumbprints.length`)
- Per-binding actions:
  - **Revoke** — with confirmation dialog ("This will prevent all devices using this agent identity from renewing. Are you sure?")
- Revoked bindings shown in a separate "Revoked" section (greyed out, no actions)
- Empty state: "No agents registered yet."

### 6.2 API Calls from UI

All `/person/*` API calls require the `person_token` bearer token. The UI stores it in `sessionStorage` on first load (prompted via a simple input dialog if not present — no full auth flow needed for a local reference implementation).

### 6.3 UX Details

- The approval flow should feel lightweight: one click to approve, no confirmation required (deny and revoke do require confirmation)
- The `label` field from the agent's registration request is the primary human-readable identifier — make it prominent
- Truncate `stable_jkt` and `agent_id` in the UI but make them copyable (click to copy)
- Show relative times ("2 minutes ago", "expires in 47 minutes") not absolute timestamps
- When the person clicks **Link to existing agent**, show a dropdown of active bindings with their labels. On select, confirm with: "This will add this device to [label]. The device will share the same agent identity."
- Pending registrations that are close to expiry (< 5 min) should show a visual warning

### 6.4 Static Mount

```python
# In agent_server/http/app.py
from fastapi.staticfiles import StaticFiles
app.mount("/ui", StaticFiles(directory="agent_server/ui", html=True), name="ui")
```

UI files live in `agent_server/ui/`:
```
agent_server/ui/
    index.html
    registrations.html
    agents.html
    style.css          # Matches person server UI style
    app.js             # Shared JS utilities (fetch wrapper, token storage, relative time)
```

---

## Part 7: Implementation Order

### Phase 1: Foundation

1. Project scaffolding: `agent_server/` directory structure, FastAPI app skeleton, `AgentServerSettings`
2. Data models: `PendingRegistration`, `Binding` dataclasses in `models.py`
3. In-memory stores: `PendingRegistrationStore`, `BindingStore`, replay cache
4. Metadata endpoints: `GET /.well-known/aauth-agent.json`, `GET /.well-known/jwks.json` (placeholder JWKS)
5. Agent ID generation + validation (`aauth:<uuid>@<domain>` format, spec character rules)
6. Startup warning for default `person_token`

### Phase 2: Signing + Token Issuance

7. Ed25519 key management: generate via `aauth.generate_ed25519_keypair()`, load from / persist to PEM using `cryptography`
8. JWKS generation: `aauth.generate_jwks()` with current + previous key
9. Live JWKS endpoint (replaces placeholder from Phase 1)
10. `AgentTokenFactory` wrapping `aauth.create_agent_token()`

### Phase 3: HTTP Signature Verification

11. `HttpSigVerifier` wrapping `aauth.verify_signature()` for `hwk` and `jkt-jwt` schemes
12. Replay protection: 60-second `(thumbprint, created)` in-memory cache
13. FastAPI dependency `require_http_sig` → `VerifiedRequest`
14. FastAPI dependency `require_person` → validates `Authorization: Bearer <person_token>`

### Phase 4: Registration + Approval Flow

15. `POST /register`: verify HTTP sig → check for existing binding → create `PendingRegistration` → 202
16. `GET /pending/{id}`: verify HTTP sig (same eph key) → check status → return token/pending/denied
17. `GET /person/registrations`: list pending (person auth)
18. `POST /person/registrations/{id}/approve`: create binding → mark pending approved
19. `POST /person/registrations/{id}/deny`: mark denied
20. `POST /person/registrations/{id}/link`: add stable_jkt to existing binding → mark pending approved
21. `GET /person/bindings`: list all bindings
22. `POST /person/bindings/{agent_id}/revoke`: revoke binding

### Phase 5: Renewal Flow

23. `POST /refresh`: `aauth.verify_signature()` (jkt-jwt) → extract stable JKT from verified result → lookup binding → issue new token

### Phase 6: UI

24. `agent_server/ui/style.css` — base styles matching person server UI
25. `agent_server/ui/app.js` — shared utilities: fetch wrapper with bearer token, relative time, copy-to-clipboard
26. `agent_server/ui/index.html` — dashboard
27. `agent_server/ui/registrations.html` — pending registrations with approve/deny/link actions
28. `agent_server/ui/agents.html` — my agents with revoke action
29. Mount `/ui` static files in `app.py`

### Phase 7: Polish

30. Error responses: spec error codes (`invalid_request`, `invalid_signature`, `invalid_key`, `invalid_jwt`, `expired_jwt`, `unsupported_algorithm`, `invalid_input`)
31. Optional `POST /revoke`
32. Key rotation: multiple keys in JWKS
33. Demo script: `scripts/agent-demo.sh`

---

## Part 8: Verification and Testing

### Unit Tests

- Agent ID validation: valid/invalid per spec character rules
- Agent token creation: correct claims, correct `typ`/`dwk`, proper signing, `exp` ≤ 24h
- JWK Thumbprint: RFC 7638 compliance via `aauth.calculate_jwk_thumbprint()`
- Pending registration store: create, approve, deny, expiry, find_by_stable_jkt
- Binding store: create, lookup by JKT, add_stable_key, revoke
- Signature verification: valid `hwk`, valid `jkt-jwt`, expired `created`, replayed request

### Integration Tests

- **Full registration flow**: `POST /register` → `GET /pending/{id}` (202) → person approves → `GET /pending/{id}` (200 + token)
- **Full renewal flow**: `POST /refresh` with `jkt-jwt` → verify new token has same `sub`, different `cnf.jwk`
- **Denied registration**: person denies → `GET /pending/{id}` returns 403
- **Expired pending**: let registration expire → `GET /pending/{id}` returns 410
- **Re-registration of known device**: stable JKT already in a binding → immediate token (no pending)
- **Device linking**: `POST /person/registrations/{id}/link` → stable JKT added to existing binding → next poll returns token
- **Revoked binding**: revoke → `POST /refresh` returns 401
- **JWKS verification**: token signature verifies against `GET /.well-known/jwks.json`

### End-to-End Demo Script

```bash
#!/bin/bash
# scripts/agent-demo.sh
# Prerequisites: openssl, step-cli or jwt-cli for JWT creation, jq

BASE=http://localhost:8800
PERSON_TOKEN=changeme

# 1. Generate stable + ephemeral key pairs
openssl genpkey -algorithm ed25519 -out /tmp/stable-priv.pem
openssl pkey -in /tmp/stable-priv.pem -pubout -out /tmp/stable-pub.pem
openssl genpkey -algorithm ed25519 -out /tmp/eph-priv.pem
openssl pkey -in /tmp/eph-priv.pem -pubout -out /tmp/eph-pub.pem

# 2. Fetch metadata
curl -s $BASE/.well-known/aauth-agent.json | jq .
curl -s $BASE/.well-known/jwks.json | jq .

# 3. Register (agent signs POST with eph_priv, sends stable_pub in body)
# Signature headers computed by the agent's aauth.sign_request() call
CREATED=$(date +%s)
# ... compute Signature-Input, Signature, Signature-Key headers ...
RESPONSE=$(curl -s -D - -X POST $BASE/register \
  -H "Content-Type: application/json" \
  -H "Signature-Input: sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\");created=$CREATED" \
  -H "Signature: sig=:...(eph_priv signature)...:" \
  -H "Signature-Key: sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"...(eph_pub base64url)...\"" \
  -d '{"stable_pub": {"kty": "OKP", "crv": "Ed25519", "x": "..."}, "label": "Demo Agent"}')
PENDING_ID=$(echo "$RESPONSE" | grep -i location | awk '{print $2}' | tr -d '\r' | sed 's|/pending/||')
echo "Pending ID: $PENDING_ID"

# 4. Poll — should be pending (request MUST be signed with same eph_priv)
CREATED=$(date +%s)
curl -s $BASE/pending/$PENDING_ID \
  -H "Signature-Input: sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\");created=$CREATED" \
  -H "Signature: sig=:...(eph_priv signature)...:" \
  -H "Signature-Key: sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"...(eph_pub)...\"" | jq .

# 5. Person approves via API
curl -s -X POST $BASE/person/registrations/$PENDING_ID/approve \
  -H "Authorization: Bearer $PERSON_TOKEN" | jq .

# 6. Poll again — should return agent_token (signed with same eph_priv)
CREATED=$(date +%s)
AGENT_TOKEN=$(curl -s $BASE/pending/$PENDING_ID \
  -H "Signature-Input: sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\");created=$CREATED" \
  -H "Signature: sig=:...(eph_priv signature)...:" \
  -H "Signature-Key: sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"...(eph_pub)...\"" | jq -r .agent_token)
echo "Agent token: $AGENT_TOKEN"

# 7. Refresh (generate new eph key, build jkt-s256+jwt, sign request with new eph_priv)
openssl genpkey -algorithm ed25519 -out /tmp/new-eph-priv.pem
openssl pkey -in /tmp/new-eph-priv.pem -pubout -out /tmp/new-eph-pub.pem
# Build jkt-jwt: header { alg: EdDSA, typ: jkt-s256+jwt, jwk: stable_pub },
#               payload { iss: urn:jkt:sha-256:<thumbprint>, cnf: { jwk: new_eph_pub }, iat, exp }
# Sign with stable_priv
# Then sign HTTP request with new_eph_priv
curl -s -X POST $BASE/refresh \
  -H "Signature-Input: sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\");created=$(date +%s)" \
  -H "Signature: sig=:...(new_eph_priv signature)...:" \
  -H "Signature-Key: sig=jkt-jwt;jwt=\"...(jkt-jwt token)...\"" | jq .
```

---

## Part 9: Key Spec References

| Topic | Source | Lines |
|-------|--------|-------|
| Agent Token Structure | `draft-hardt-aauth-protocol.md` | 504-526 |
| Agent Token Verification | `draft-hardt-aauth-protocol.md` | 536-545 |
| Agent Server Metadata | `draft-hardt-aauth-protocol.md` | 2123-2152 |
| Agent Identifiers | `draft-hardt-aauth-protocol.md` | 475-490 |
| Server Identifiers | `draft-hardt-aauth-protocol.md` | 2080-2103 |
| HTTP Sig Verification Procedure | `draft-hardt-aauth-protocol.md` | 2061-2070 |
| Covered Components | `draft-hardt-aauth-protocol.md` | 2044-2052 |
| Signature Algorithms | `draft-hardt-aauth-protocol.md` | 2023-2025 |
| Token Revocation | `draft-hardt-aauth-protocol.md` | 1985-2017 |
| JWKS Caching | `draft-hardt-aauth-protocol.md` | 2072-2076 |
| Desktop/User Login Pattern | `draft-hardt-aauth-protocol.md` | 2546-2557 |
