# Mission Manager evolution notes

This document records design intent and planned hardening for the reference Mission Manager (MM), especially the **user interaction / consent** path. It complements the README and the plan documents under `.cursor/plans/`.

## Interaction flow (reference implementation)

After `POST /token` returns **202** with `Location`, `Retry-After`, and `AAuth-Requirement` (including an interaction `code` and URL), a human or a human-facing system completes consent:

1. **`GET /interaction?code=<code>`** — Returns JSON describing the pending operation (`pending_id`, `scopes`, optional `justification`, mission summary when applicable). The handler also marks the pending record as interacting.
2. **`POST /interaction/{pending_id}/decision`** — Body `{"approved": true}` (or `false`, or clarification fields per `UserDecisionBody`) records the user’s choice. On approval for a token pending request, the MM resolves the pending record so **`GET` on the original `Location`** can return the issued auth material.

The demo script `scripts/mm-demo.sh` exercises this sequence explicitly.

## Security posture today

- **Agent routes** (e.g. `POST /mission`, `POST /token`, pending poll/delete) use **`X-AAuth-Agent-Id`** when `AAUTH_MM_INSECURE_DEV=true` (dev convenience, not production identity).
- **Admin** routes can require **`Authorization: Bearer <token>`** when `AAUTH_MM_ADMIN_TOKEN` is set.
- **`GET /interaction` and `POST /interaction/{pending_id}/decision` are not authenticated** in the default “simple” setup. Setting `AAUTH_MM_REQUIRE_USER_SESSION=true` is reserved; the HTTP layer does not yet enforce a real user session (see `mm/http/config.py` and `mm/http/app.py`).

That openness is intentional for local demos and tests. **It is not appropriate for production** without an additional trust boundary.

## Who should be allowed to consent? (protocol alignment)

In AAuth (see `.cursor/plans/draft-hardt-aauth-protocol.md`), the **Mission Manager (MM)** “represents the legal person to the rest of the protocol,” is “trusted by the legal person to … handle consent,” and **brokers authorization** by federating with **resource authorization servers (ASes)**. The same document states a clean split: **the MM handles user consent and identity; the AS handles resource policy**—neither overlaps the other’s role.

So consent at the MM’s **interaction** endpoints is **not** a resource-side concern. The **resource** trusts its **AS** for access policy; the MM is a different party in a different trust domain. **Who may approve or deny on the MM** is therefore whoever the **MM** accepts as authenticated and authorized to act for the **legal person** (the user or organization on whose behalf the agent operates)—not “whoever the resource trusts” in the abstract.

Implications for this codebase:

- **Arbitrary public callers** must not be able to drive `/interaction` … `/decision` without the MM verifying identity (session, federation, or another policy the MM operator defines).
- The **agent** must not use the same credential it uses for `POST /token` (or equivalent agent identity) to post a **decision**, or the MM would allow **self-approval** instead of a distinct **user / legal-person** authorization step (step 4 vs step 5 in the protocol overview).

Typical patterns to implement later:

- **First-party consent UI** — The legal person signs in to an experience the **MM operator** controls (OIDC, SSO, session cookie). The browser or a **BFF** calls the MM only after authentication; the MM binds the pending request to that principal (or an allowed delegate).
- **Trusted backend API** — A service the **MM operator** trusts (mTLS, service JWT, private network) that has already verified the legal person and then calls `POST .../decision` for the correct `pending_id`.

The **interaction `code`** is an opaque capability for opening the flow. In production it should be combined with **HTTPS**, **short TTLs**, **abuse controls**, and **binding** to a principal the MM recognizes. If `pending_id` values are predictable, **knowledge of `pending_id` alone must not** be sufficient to approve; the high-entropy `code` and server-side checks mitigate that when designed together.

**User credentials vs agent credentials:** Sessions or tokens for the **legal person** (human or org process) are distinct from **agent** proof-of-possession and agent endpoints. The consent step should validate the former (or a delegate the MM trusts), not conflate them with the agent’s credentials or with **auth tokens** issued by the resource’s AS for calling the resource.

## Configuration hooks

| Setting | Role |
|--------|------|
| `AAUTH_MM_REQUIRE_USER_SESSION` | Reserved flag for future enforcement of user session (or equivalent) on `/interaction` routes. |
| `AAUTH_MM_INSECURE_DEV` | Dev-only agent identification; replace with real agent auth in production. |
| `AAUTH_MM_ADMIN_TOKEN` | Protects admin/mission-control style routes when set. |

## Summary

The reference MM implements the **protocol shape** for deferred token grant and user decision. **Who may use the interaction endpoints** is an **MM trust and authentication** problem (legal person / MM operator policy), not resource policy—that remains with the AS. Deployment should add session-backed UI, BFF, or internal trusted API—or future in-MM enforcement once `require_user_session` (or a richer policy) is implemented.
