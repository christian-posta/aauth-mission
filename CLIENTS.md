# Agent client guide: register, token, refresh

This document is for **HTTP clients** that obtain an **`agent_token`** from an AAuth-style **Agent Server** using a **stable Ed25519 identity** plus **ephemeral signing keys**, HTTP Message Signatures ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html)), and a **`Signature-Key`** header per the **HTTP Signature Keys** draft ([draft-hardt-httpbis-signature-key](https://dickhardt.github.io/signature-key/draft-hardt-httpbis-signature-key.html)). Normative background for AAuth fields and tokens lives in [SPEC.md](SPEC.md).

## Signing model (what to implement)

| Step | `Signature-Key` scheme | Keys |
|------|------------------------|------|
| `POST /register` and registration poll | **`hwk`** | Request is signed with an **ephemeral** Ed25519 key. That ephemeral **public** JWK is carried in `Signature-Key` (`hwk`). |
| `POST /refresh` | **`jkt-jwt`** | A short-lived JWT signed by the **stable** private key goes in `Signature-Key`; its payload names the stable identity (`iss` as a JKT URN) and delegates proof-of-possession to a **new** ephemeral key in `cnf.jwk`. The **HTTP request** is signed with that **new** ephemeral private key. |

The **stable** public key is always sent in the JSON body of **`POST /register`** as **`stable_pub`** (Ed25519 public JWK). The server derives a stable thumbprint (JKT) for binding and refresh lookup.

Use the **`aauth`** library for signing and verification helpers (for example `aauth.sign_request`, `aauth.generate_ed25519_keypair`, `aauth.public_key_to_jwk`, `aauth.calculate_jwk_thumbprint`). Align the **`aauth`** package version with whatever the server operator documents.

---

## 1. Discovery

### `GET /.well-known/aauth-agent.json` (200)

Use at least:

- **`issuer`** — expect JWT `iss` on **`agent_token`** to match this.
- **`jwks_uri`** — JWKS for verifying **`agent_token`** signatures (`kid` in the JWT header).
- **`registration_endpoint`** — URL for **`POST /register`** (often `{origin}/register`).
- **`refresh_endpoint`** — URL for **`POST /refresh`** (often `{origin}/refresh`).

### `GET /.well-known/jwks.json` (200)

JWKS for the server’s signing keys (same resource as **`jwks_uri`** when that URI points here).

---

## 2. Register — `POST /register`

**Headers**

- `Content-Type: application/json`
- HTTP Message Signature fields from `aauth.sign_request(..., sig_scheme="hwk", ...)` using the **ephemeral** private key (library supplies `Signature-Input`, `Signature`, `Signature-Key`).

**Body (JSON)**

```json
{
  "stable_pub": { "kty": "OKP", "crv": "Ed25519", "x": "<base64url>" },
  "agent_name": "Human-readable name for this agent (required)"
}
```

- **`stable_pub`** — long-term Ed25519 public JWK for the agent.
- **`agent_name`** — required display name (trimmed; 1–256 characters after trimming) shown in approval and binding UIs. Not only whitespace.
- The same JSON object shape (including required **`agent_name`**) is used for operator **`POST /person/bindings`** on deployments that pre-trust a stable public key.
- The **ephemeral** public key must **not** be duplicated in the body; it appears only under **`hwk`** in `Signature-Key`. The server ties the pending row to that ephemeral key; later polls must use the **same** ephemeral key.

**Outcomes**

1. **200** — `{ "agent_token": "<JWT>" }` — stable identity already bound and active; token is issued immediately and is bound to the **current** ephemeral key (`cnf.jwk` in the JWT).

2. **202** — Registration is waiting for **operator approval** (or similar policy). Body typically includes `status: "pending"` and an expiry time. Headers should include **`Location`** (absolute or relative URL to poll) and **`Retry-After`**. The client must **`GET` the poll URL given in `Location`** (do not assume a fixed path prefix across servers).

**Errors (typical)**

- **401** — missing or invalid HTTP signature (structured error body per server).
- **400** — invalid JSON.
- **422** — body validation (for example missing **`agent_name`**, only-whitespace name, or unknown extra JSON fields; servers using Pydantic typically reject legacy **`label`** as unknown).

### Pre-trust: same agent URLs, different who goes first

If a **person or operator** has already **created a binding** for your stable key (e.g. **`POST /person/bindings`** on the same deployment, authenticated with a person token, with the same **`stable_pub`** and an **`agent_name`**) *before* you call **`POST /register`**, that only affects **server policy**, not your wire protocol:

- **You still use the same agent-facing URLs** as everyone else: **`POST /register`** (from **`registration_endpoint`** in **`/.well-known/aauth-agent.json`**) and, if you get a **202**, the **`GET` poll** URL from the **`Location`** response header. **`POST /refresh`** is always the same **`refresh_endpoint`**.
- The operator path **`POST /person/bindings`** is **not** part of the agent’s client library — it is a separate, person-authenticated administrative API. The agent does not substitute it for **`POST /register`**.

**What actually changes** when a binding already exists and is not revoked: your **first** **`POST /register`** for that **`stable_pub`** is more likely to return **200** with **`agent_token`** immediately (no pending row, no poll). If no binding exists yet, you get **202** and poll as usual.

Your **`agent_name`** on **`POST /register`** should still be sent in all cases. In the **reference Agent Server in this repository**, a successful **POST /register** for an **already-bound** stable key also **updates** the stored display name; other products may differ. Treat the request body as the same for pre-trusted and self-serve registration.

---

## 3. Poll until registered — `GET` (same host as `Location`)

Use the **same** ephemeral key and **`hwk`** as for **`POST /register`**. No body.

- **202** — still pending; respect **`Retry-After`** and poll again.
- **200** — `{ "agent_token": "<JWT>" }` — approved; token is bound to the registration ephemeral key.

**Errors (typical)**

- **401** — bad signature, or ephemeral key **does not match** the one used at registration.
- **404** — unknown pending id.
- **403** — registration denied.
- **410** — pending expired.

---

## 4. Refresh — `POST /refresh`

**Required:** `Signature-Key` scheme **`jkt-jwt`**, not **`hwk`**.

1. Generate a **new** ephemeral Ed25519 key pair.
2. Build a **delegation JWT** signed by the **stable** private key (short TTL, e.g. minutes). Payload (conceptually) includes:
   - **`iss`**: stable identity as `urn:jkt:sha-256:<thumbprint(stable_pub)>`
   - **`iat`**, **`exp`**
   - **`cnf`**: `{ "jwk": <new ephemeral public JWK> }` — the key that signs **this** HTTP request
3. Call `aauth.sign_request(..., sig_scheme="jkt-jwt", jwt=<delegation_jwt>, private_key=<new_ephemeral_priv>, ...)` for **`POST /refresh`** with an **empty** body.

**200** — `{ "agent_token": "<JWT>" }` — same **`sub`** (`agent_id`), new **`cnf.jwk`** for the new ephemeral key.

**401** — wrong scheme, unknown or revoked binding, or signature failure.

---

## 5. Using **`agent_token`**

1. Confirm **`iss`** matches **`issuer`** from **`/.well-known/aauth-agent.json`**.
2. Verify the JWT with keys from **`jwks_uri`** / **`/.well-known/jwks.json`** (`kid` in the JWT header).
3. Treat **`sub`** as **`agent_id`**.
4. Use **`cnf.jwk`** as the proof-of-possession key for subsequent signed calls **as defined by AAuth** toward other endpoints (not necessarily the same as register/refresh signing rules on this server).

---

## 6. End-to-end sequence (minimal)

1. **`GET /.well-known/aauth-agent.json`**
2. **`POST /register`** — body with **`stable_pub`** and required **`agent_name`**; sign with ephemeral key, **`hwk`**
3. If **202** — **`GET`** the URL from **`Location`** on the same schedule as **`Retry-After`**, same ephemeral key, **`hwk`**, until **200** or a terminal error. *(If a binding for this **`stable_pub`** was pre-created by an operator, step 2 may return **200** here and you skip the poll.)*
4. **`POST /refresh`** when you need a new token — new ephemeral key + stable-signed delegation JWT, **`jkt-jwt`**

A runnable reference implementation (Python, **`aauth`**) that exercises the same steps: `scripts/agent-server-signed-walkthrough.py` in this repository (`--base` URL; **`--pending-prefix`** must match the poll path your server puts on **`Location`** after **202**, e.g. `/pending` vs `/register/pending`).

---

## 7. Error bodies (typical)

- Signature and AAuth validation failures on agent routes: **401** with structured JSON (`error` / `error_description` or equivalent).
- Pending denied: **403** with `{ "error": "denied" }` (shape may vary slightly).
- Pending expired: **410** with `{ "error": "expired" }`.

---

## Out of scope here

- Exact **`Signature-Input`** component ordering (handled by **`aauth`** and RFC 9421).
- How **`agent_token`** is presented to resource servers and Person Server flows — see **SPEC.md** and your product’s integration docs.
