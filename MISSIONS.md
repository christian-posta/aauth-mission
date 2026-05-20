# Mission-aware governance in this Person Server

This server implements AAuth missions per the protocol draft *plus* two PS-local
governance layers on top:

- **Layer 1 — Mission-aware `/token` decisions.** Before issuing an auth token the PS
consults a `MissionEvaluator` that reads the mission text, the full mission log, and
the request summary, then returns one of `allow` / `escalate` / `clarify` / `deny`.
- **Layer 2 — Approved-tools gating on `/permission`.** A permission request is granted
immediately if the action is in the mission's `approved_tools` list, and escalated to
the user otherwise.

The protocol itself only gives you **correlation** — every action references an approved
mission by `s256`. It does not give **containment** — proof that an action is within the
approved authority. Layers 1 and 2 are where containment lives in this codebase.

For the conceptual background, read Karl McGuinness's posts in this order:

1. *From Passports to Power of Attorney* — the Execution Mandate idea.
2. *Mission-Bound OAuth* — what OAuth misses about delegated agent authority.
3. *Mission Architecture on AAuth* — three artifacts: durable record, projected ref,
  machine-evaluable authority model.
4. *AAuth Now Has a Mission Layer* — what v01 added and the six gaps it still has.
5. *Sessions Are Not Missions* — sessions preserve execution, missions preserve
  legitimacy.

URLs are in `~/.claude/projects/-Users-ceposta-python-aauth-person-server/memory/ref_karl_mcguinness_missions.md`.

---

## Layer 2 — approved-tools gating

### Behavior

`POST /permission` with body `{action, description, parameters, mission}`:


| Case | Mission    | Action in `approved_tools`? | Response                                                                                                         |
| ---- | ---------- | --------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| 1    | absent     | n/a                         | `200 {"permission":"granted"}` (spec-permissive)                                                                 |
| 2    | active     | yes                         | `200 {"permission":"granted"}`, logged as `decided_by=approved_tools`                                            |
| 3    | active     | no                          | `202` deferred; user decides via consent UI; agent polls `/pending/{id}` for `{"permission":"granted"|"denied"}` |
| 4    | terminated | n/a                         | `403 {"error":"mission_terminated"}`                                                                             |


The deferred path goes through exactly the same pending/consent machinery as a token
request — only the consent UI changes to render the action name, description, and
parameters. See `ps/http/static/consent.html` and `portal/ui/consent.html`.

### Key source files

- `ps/impl/ps_governance.py:42` — `post_permission` decision branches
- `ps/impl/memory_pending.py` — `create_permission_pending`
- `ps/impl/memory_consent.py` — `record_decision` permission branch
- `ps/http/app.py:445` — `/permission` route handling 202 deferred

---

## Layer 1 — mission-aware `/token` decisions

### Behavior

`POST /token` with a mission ref triggers the evaluator after `require_active_mission`
and after resource-token verification (when in secure mode). The evaluator returns:


| Decision   | Effect                                                                                   |
| ---------- | ---------------------------------------------------------------------------------------- |
| `allow`    | issue auth token immediately, skip the consent prompt even if scope normally requires it |
| `escalate` | fall through to user consent; the reason is shown in the consent UI as "PS guidance"     |
| `clarify`  | return `202` with `AAuth-Requirement: clarification` and the evaluator's question        |
| `deny`     | `403 {"error":"mission_denied", "error_description": "..."}`                             |


Every decision is appended to the mission log as a `token_request` entry with
`stage=evaluator`.

### Implementations

Two are wired by default:

- `**KeywordMissionEvaluator*`* (`ps/impl/keyword_evaluator.py`) — deterministic rules
over the mission description tokens, the `approved_tools` list, and the request's
resource issuer + scope. Has explicit deny tokens (`deny:`, `never:`, `do not:`,
`forbid:`). Used for tests and the demo.
- `**NoopMissionEvaluator**` — always returns `escalate`. Useful for forcing the consent
path on every mission-scoped token request.

Set via env var:

```
AAUTH_PS_MISSION_EVALUATOR=keyword   # the demo default
AAUTH_PS_MISSION_EVALUATOR=noop      # always escalate
AAUTH_PS_MISSION_EVALUATOR=off       # disable (default)
```

To plug in an LLM-backed or policy-engine evaluator, implement
`ps.service.mission_evaluator.MissionEvaluator` and extend `_build_evaluator` in
`ps/impl/__init__.py`.

### Key source files

- `ps/service/mission_evaluator.py` — Protocol + `EvaluationDecision` + `TokenRequestSummary`
- `ps/impl/keyword_evaluator.py` — deterministic implementation
- `ps/impl/memory_token.py` — `request_token` invokes `_apply_evaluator` after token verify
- `ps/exceptions.py:MissionDeniedError` — 403 mapping
- `ps/http/config.py:mission_evaluator` — settings hook

---

## Manual demo walkthrough

### Start the PS with Layer 1 enabled

From the repo root, in one terminal:

```
nAAUTH_PS_INSECURE_DEV=true \
AAUTH_PS_ADMIN_TOKEN=mytoken \
AAUTH_PS_MISSION_EVALUATOR=keyword \
AAUTH_PS_SIGNING_KEY_PATH= \
AAUTH_PS_TRUST_FILE= \
AAUTH_PS_CONSENT_SCOPES_FILE= \
uv run uvicorn ps.http.app:app --host 127.0.0.1 --port 8766
```

(Or for the unified portal — same env vars, run `portal.http.app:app`.)

### Run the demo script

In another terminal:

```
chmod +x scripts/mission-demo.sh
BASE_URL=http://127.0.0.1:8766 ADMIN_TOKEN=mytoken ./scripts/mission-demo.sh
```

The script walks through six sections (printed inline). Each shows request, response,
and any extracted IDs:

- **§A — Approve a mission.** The mission description carries a deny token
(`do not: delete`) so we can also exercise the deny rule via tests. `approved_tools`
contains just `WebSearch`.
- **§B — `/permission` for `WebSearch`** (in `approved_tools`). Expect `200 granted`.
- **§C — `/permission` for `BookFlight`** (outside `approved_tools`). Expect `202`. The
script fetches `/consent?code=…` to show what the user sees (note
`permission_action`, `permission_description`, `permission_parameters`), then approves
via `/consent/{pid}/decision`, then polls `/pending/{pid}` to read the terminal
`{"permission":"granted"}`.
- **§D — `/permission` for `DeleteAccount`** (outside `approved_tools`). Same flow, but
the script denies. Terminal is `{"permission":"denied"}` (a normal 200 body, not 403 —
the user's decision is the result).
- **§E — `/token` under the mission.** In insecure-dev mode there are no resource claims,
so the keyword evaluator returns `escalate`. The script fetches the consent context
and asserts `evaluator_reason` is present. This is where Layer 1 surfaces "PS
guidance" to the user.
- **§F — `GET /missions/{s256}`.** Prints the full mission log so you can see every
decision the PS recorded.

### Reading the mission log

After running the demo, the log should contain (in order):

1. `mission_approved` — the original approval.
2. `permission` — `result=granted`, `decided_by=approved_tools` (§B).
3. `permission` — `result=deferred`, `decided_by=user_pending` (§C ask).
4. `permission` — `result=granted`, `decided_by=user` (§C decision).
5. `permission` — `result=deferred`, `decided_by=user_pending` (§D ask).
6. `permission` — `result=denied`, `decided_by=user` (§D decision).
7. `token_request` — `stage=evaluator`, `decision=escalate`, `reason="no overlap …"` (§E).

This is the audit trail Karl talks about as "correlation": the log proves which actions
the PS associated with which mission. The decisions themselves are Layer 1 / 2
containment.

### Exercising Layer 1's other decisions

The shell demo can only easily show `escalate` because insecure-dev mode has no resource
claims to drive `allow` / `clarify` / `deny`. The other paths are covered by tests:

```
uv run pytest tests/test_mission_evaluator.py -v        # unit, all rules
uv run pytest tests/test_token_with_evaluator.py -v     # end-to-end via HTTP + injected evaluator
```

Notably:

- `test_token_evaluator_allow_issues_immediately` — `allow` bypasses consent.
- `test_token_evaluator_deny_path_unit_via_broker` — `deny` raises `MissionDeniedError`
→ HTTP 403 `mission_denied`.
- `test_token_evaluator_clarify_returns_clarification_deferred` — `clarify` returns 202
with `AAuth-Requirement: clarification`.

To wire `allow` / `clarify` / `deny` into a real demo, use the mode-3 secure-token setup
(`tests/test_ps_token_endpoint.py` shows how to mint a real `aa-resource+jwt` against a
test RS keypair). The evaluator sees `resource_iss` and `resource_scope` from the
verified claims; the keyword rules then fire.

---

## What's NOT implemented (Karl's remaining gaps)

Karl identifies six gaps in the v01 protocol. Layers 1+2 here address some, not all.


| Gap                                                               | Status here                                                                                                                                                                                                           |
| ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1. Text-first authority** (no machine-evaluable model)          | partial — the keyword evaluator is a thin shim, not a real authority model. A production deployment would replace it with an LLM-backed or policy-engine evaluator implementing the same `MissionEvaluator` Protocol. |
| **2. Narrow lifecycle** (only `active` / `terminated`)            | not started — we keep the spec's two wire states. An internal sub-state on `Mission` (e.g. `suspended`, `completing`) is the suggested next step.                                                                     |
| **3. Revocation timing gap** (in-flight tokens after termination) | not started — `IssuedTokenStore` records issuance but no cascade-on-terminate.                                                                                                                                        |
| **4. Weak downstream attenuation** (delegation chain bounds)      | n/a — this server is one hop.                                                                                                                                                                                         |
| **5. Runtime drift** (cumulative behavior outside intent)         | partial — the evaluator gets the whole log on every call so it *can* notice drift, but the keyword impl doesn't. An LLM evaluator would.                                                                              |
| **6. Cross-domain semantics**                                     | n/a — single-PS deployment.                                                                                                                                                                                           |


The next-most-valuable change after Layers 1+2 is probably gap 3 (revocation cascade)
because it has a clean implementation: walk `IssuedTokenStore` on mission terminate and
mark matching tokens revoked, then have the auth-token verifier check the revocation
list. Gap 1 is interesting but unbounded scope.