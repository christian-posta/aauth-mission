#!/usr/bin/env bash
# Interactive walkthrough for AGENTSERVER.md §5 — curl flows in insecure_dev mode.
#
# Prerequisites:
#   - Agent server running with AAUTH_AS_INSECURE_DEV=true (see AGENTSERVER.md §2).
#   - curl, openssl, python3 on PATH; jq optional (prettier JSON).
#
# Usage:
#   ./scripts/agent-server-walkthrough.sh
#   BASE=http://127.0.0.1:8800 PERSON_TOKEN=mytoken ./scripts/agent-server-walkthrough.sh
#   BASE=http://127.0.0.1:8765 PENDING_POLL_PREFIX=/register/pending ./scripts/agent-server-walkthrough.sh  # unified portal
#   AUTO=1 ./scripts/agent-server-walkthrough.sh    # run all steps without "Press Enter"
#
# Environment:
#   BASE                 — server origin (default: http://localhost:8800)
#   PERSON_TOKEN         — AAUTH_AS_PERSON_TOKEN value (default: mytoken)
#   PENDING_POLL_PREFIX — path prefix for registration poll GET after POST /register (default: /pending).
#                         Use /register/pending when targeting the unified portal (portal.http.app);
#                         standalone agent_server keeps /pending/{id}.
#   AUTO                 — if set to 1, skip pauses between steps
#   SKIP_OPTIONAL        — if set to 1, skip re-register, list/deny/revoke extras

set -euo pipefail

BASE="${BASE:-http://localhost:8800}"
BASE="${BASE%/}"
PERSON_TOKEN="${PERSON_TOKEN:-mytoken}"
PENDING_POLL_PREFIX="${PENDING_POLL_PREFIX:-/pending}"
AUTO="${AUTO:-0}"
SKIP_OPTIONAL="${SKIP_OPTIONAL:-0}"

have_jq() { command -v jq >/dev/null 2>&1; }

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
sub() { printf '  %s\n' "$*"; }
ok() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad() { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; }

pause() {
  if [[ "$AUTO" == "1" ]]; then
    return
  fi
  read -r -p "Press Enter for the next step… " _
}

http_code_from_headers() {
  head -1 "$1" | sed -n 's:^HTTP/[^ ]* \([0-9]*\).*:\1:p'
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    bad "missing required command: $1"
    exit 1
  }
}

ed25519_pub_x_b64url() {
  # $1: path to Ed25519 private key PEM
  openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 | tr '+/' '-_' | tr -d '='
}

verify_b64url_x() {
  local name=$1 val=$2
  local len
  len=${#val}
  if [[ "$len" -eq 43 ]]; then
    ok "${name} length is 43 (32 bytes base64url, no padding)"
  else
    bad "${name} expected length 43, got ${len}"
    return 1
  fi
}

step_check_server() {
  say "Step 0 — Verify server (well-known)"
  local hdr body code
  hdr=$(mktemp)
  body=$(mktemp)
  # Embed paths now: RETURN may run after locals are torn down (set -u).
  trap "rm -f '${hdr}' '${body}'" RETURN
  curl -sS -D "$hdr" -o "$body" "${BASE}/.well-known/aauth-agent.json" || true
  code=$(http_code_from_headers "$hdr")
  if [[ "$code" != "200" ]]; then
    bad "GET /.well-known/aauth-agent.json → HTTP ${code} (expected 200). Is the server up at ${BASE}?"
    exit 1
  fi
  ok "well-known responds with HTTP 200"
  if have_jq; then
    sub "$(jq . <"$body" | sed 's/^/    /')"
    if jq -e '.registration_endpoint' "$body" >/dev/null 2>&1; then
      ok "JSON contains registration_endpoint"
    else
      bad "JSON missing registration_endpoint"
      exit 1
    fi
  else
    sub "$(sed 's/^/    /' "$body")"
    if grep -q registration_endpoint "$body"; then
      ok "response mentions registration_endpoint"
    else
      bad "response missing registration_endpoint"
      exit 1
    fi
  fi
}

main() {
  require_cmd curl
  require_cmd openssl
  require_cmd python3

  local WORK
  WORK=$(mktemp -d)
  trap "rm -rf '${WORK}'" EXIT

  say "AGENTSERVER.md §5 — curl walkthrough (insecure_dev)"
  sub "Target: ${BASE}"
  sub "Person token: ${PERSON_TOKEN}"
  sub "PENDING_POLL_PREFIX=${PENDING_POLL_PREFIX}"
  sub "AUTO=${AUTO} SKIP_OPTIONAL=${SKIP_OPTIONAL}"

  step_check_server
  pause

  say "Step 1 — Generate Ed25519 keys (stable + ephemeral)"
  openssl genpkey -algorithm ed25519 -out "${WORK}/stable-priv.pem" 2>/dev/null
  openssl pkey -in "${WORK}/stable-priv.pem" -pubout -out "${WORK}/stable-pub.pem" 2>/dev/null
  openssl genpkey -algorithm ed25519 -out "${WORK}/eph-priv.pem" 2>/dev/null
  openssl pkey -in "${WORK}/eph-priv.pem" -pubout -out "${WORK}/eph-pub.pem" 2>/dev/null
  ok "wrote ${WORK}/stable-priv.pem and ${WORK}/eph-priv.pem"

  local STABLE_X EPH_X
  STABLE_X=$(ed25519_pub_x_b64url "${WORK}/stable-priv.pem")
  EPH_X=$(ed25519_pub_x_b64url "${WORK}/eph-priv.pem")
  sub "Stable pub x: ${STABLE_X}"
  sub "Ephemeral pub x: ${EPH_X}"
  verify_b64url_x "STABLE_X" "$STABLE_X"
  verify_b64url_x "EPH_X" "$EPH_X"
  pause

  local CREATED SIG_INPUT SIG SIG_KEY
  CREATED=$(date +%s)
  SIG_INPUT="sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\");created=${CREATED}"
  SIG="sig=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:"
  SIG_KEY="sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"${EPH_X}\""

  say "Step 2 — POST /register (expect 202 + Location: ${PENDING_POLL_PREFIX}/…)"
  local reg_hdr reg_body reg_code
  reg_hdr=$(mktemp)
  reg_body=$(mktemp)
  curl -sS -D "$reg_hdr" -o "$reg_body" -X POST "${BASE}/register" \
    -H "Content-Type: application/json" \
    -H "Signature-Input: ${SIG_INPUT}" \
    -H "Signature: ${SIG}" \
    -H "Signature-Key: ${SIG_KEY}" \
    -d "{\"stable_pub\": {\"kty\": \"OKP\", \"crv\": \"Ed25519\", \"x\": \"${STABLE_X}\"}, \"label\": \"Walkthrough device\"}"
  reg_code=$(http_code_from_headers "$reg_hdr")
  if [[ "$reg_code" != "202" ]]; then
    bad "POST /register → HTTP ${reg_code} (expected 202 for new device)"
    sub "$(head -20 "$reg_hdr")"
    cat "$reg_body" >&2 || true
    exit 1
  fi
  ok "POST /register → HTTP 202"

  local loc
  loc=$(grep -i '^location:' "$reg_hdr" | head -1 | awk '{print $2}' | tr -d '\r' || true)
  if [[ -z "$loc" ]]; then
    bad "missing Location header"
    exit 1
  fi
  ok "Location: ${loc}"

  local PENDING_ID
  PENDING_ID=$(printf '%s' "$loc" | sed -E 's#.*/pending/##')
  # Works for both /pending/{id} and /register/pending/{id} (greedy .* then /pending/)
  if [[ -z "$PENDING_ID" ]]; then
    bad "could not parse pending id from Location"
    exit 1
  fi
  ok "Pending ID: ${PENDING_ID}"

  if have_jq; then
    sub "$(jq . <"$reg_body" | sed 's/^/    /')"
    if [[ $(jq -r .status <"$reg_body") == "pending" ]]; then
      ok "body status is \"pending\""
    else
      bad "expected body.status pending"
      exit 1
    fi
  else
    sub "$(sed 's/^/    /' "$reg_body")"
  fi
  rm -f "$reg_hdr" "$reg_body"
  pause

  say "Step 3 — GET ${PENDING_POLL_PREFIX}/{id} before approval (expect 202 + {\"status\":\"pending\"})"
  local p_hdr p_body p_code
  p_hdr=$(mktemp)
  p_body=$(mktemp)
  curl -sS -D "$p_hdr" -o "$p_body" "${BASE}${PENDING_POLL_PREFIX}/${PENDING_ID}" \
    -H "Signature-Input: ${SIG_INPUT}" \
    -H "Signature: ${SIG}" \
    -H "Signature-Key: ${SIG_KEY}"
  p_code=$(http_code_from_headers "$p_hdr")
  if [[ "$p_code" != "202" ]]; then
    bad "GET poll (before) → HTTP ${p_code} (expected 202)"
    exit 1
  fi
  ok "GET poll → HTTP 202"
  if have_jq; then
    sub "$(jq . <"$p_body" | sed 's/^/    /')"
    if [[ $(jq -r .status <"$p_body") == "pending" ]]; then
      ok "poll body status is pending"
    else
      bad "expected status pending in poll response"
      exit 1
    fi
  fi
  rm -f "$p_hdr" "$p_body"
  pause

  say "Step 4 — POST /person/registrations/{id}/approve (expect 200)"
  local a_hdr a_body a_code
  a_hdr=$(mktemp)
  a_body=$(mktemp)
  curl -sS -D "$a_hdr" -o "$a_body" -X POST \
    "${BASE}/person/registrations/${PENDING_ID}/approve" \
    -H "Authorization: Bearer ${PERSON_TOKEN}"
  a_code=$(http_code_from_headers "$a_hdr")
  if [[ "$a_code" != "200" ]]; then
    bad "approve → HTTP ${a_code} (wrong PERSON_TOKEN or server error?)"
    cat "$a_body" >&2 || true
    exit 1
  fi
  ok "approve → HTTP 200"
  if have_jq; then
    sub "$(jq . <"$a_body" | sed 's/^/    /')"
    if jq -e .agent_id "$a_body" >/dev/null 2>&1; then
      ok "response contains agent_id"
    else
      bad "approve response missing agent_id"
      exit 1
    fi
  fi
  local AGENT_ID
  AGENT_ID=$(python3 -c "import json,sys; print(json.load(open('${a_body}')).get('agent_id','').strip())")
  rm -f "$a_hdr" "$a_body"
  ok "agent_id: ${AGENT_ID}"
  pause

  say "Step 5 — GET ${PENDING_POLL_PREFIX}/{id} after approval (expect 200 + agent_token)"
  local f_hdr f_body f_code
  f_hdr=$(mktemp)
  f_body=$(mktemp)
  curl -sS -D "$f_hdr" -o "$f_body" "${BASE}${PENDING_POLL_PREFIX}/${PENDING_ID}" \
    -H "Signature-Input: ${SIG_INPUT}" \
    -H "Signature: ${SIG}" \
    -H "Signature-Key: ${SIG_KEY}"
  f_code=$(http_code_from_headers "$f_hdr")
  if [[ "$f_code" != "200" ]]; then
    bad "GET poll (after) → HTTP ${f_code} (expected 200)"
    exit 1
  fi
  ok "GET poll → HTTP 200"
  local AGENT_TOKEN
  AGENT_TOKEN=$(python3 -c "import json,sys; print(json.load(open('${f_body}')).get('agent_token',''))")
  if [[ -z "$AGENT_TOKEN" || "$AGENT_TOKEN" == "None" ]]; then
    bad "missing agent_token in response"
    exit 1
  fi
  ok "received agent_token (${#AGENT_TOKEN} chars)"
  if have_jq; then
    sub "$(jq . <"$f_body" | sed 's/^/    /')"
  fi
  rm -f "$f_hdr" "$f_body"
  pause

  say "Step 6 — Decode JWT payload; verify cnf.jwk.x matches ephemeral key"
  local PAYLOAD_X
  PAYLOAD_X=$(printf '%s' "$AGENT_TOKEN" | python3 -c "
import sys, base64, json
raw = sys.stdin.read().strip().split('.')[1]
pad = 4 - len(raw) % 4
if pad < 4:
    raw += '=' * pad
p = json.loads(base64.urlsafe_b64decode(raw))
cnf = p.get('cnf') or {}
jwk = cnf.get('jwk') or {}
print(jwk.get('x', ''))
")
  if [[ "$PAYLOAD_X" == "$EPH_X" ]]; then
    ok "cnf.jwk.x matches Signature-Key ephemeral x (${EPH_X:0:12}…)"
  else
    bad "cnf.jwk.x mismatch (expected EPH_X, got different value)"
    exit 1
  fi
  printf '%s' "$AGENT_TOKEN" | python3 -c "
import sys, base64, json
raw = sys.stdin.read().strip().split('.')[1]
pad = 4 - len(raw) % 4
if pad < 4:
    raw += '=' * pad
print(json.dumps(json.loads(base64.urlsafe_b64decode(raw)), indent=2))
" | sed 's/^/    /'
  local SUB_CLAIM
  SUB_CLAIM=$(printf '%s' "$AGENT_TOKEN" | python3 -c "
import sys, base64, json
raw = sys.stdin.read().strip().split('.')[1]
pad = 4 - len(raw) % 4
if pad < 4:
    raw += '=' * pad
print(json.loads(base64.urlsafe_b64decode(raw)).get('sub',''))
")
  if [[ "$SUB_CLAIM" == "$AGENT_ID" ]]; then
    ok "JWT sub matches approve response agent_id"
  else
    bad "JWT sub (${SUB_CLAIM}) != agent_id from approve (${AGENT_ID})"
    exit 1
  fi
  pause

  if [[ "$SKIP_OPTIONAL" == "1" ]]; then
    say "Skipping optional steps (SKIP_OPTIONAL=1)"
    say "Done — all required checks passed."
    exit 0
  fi

  say "Step 7 — Re-register same stable key with new ephemeral key (expect 200, immediate token)"
  openssl genpkey -algorithm ed25519 -out "${WORK}/eph2-priv.pem" 2>/dev/null
  local EPH2_X SIG_KEY2 rr_hdr rr_body rr_code
  EPH2_X=$(ed25519_pub_x_b64url "${WORK}/eph2-priv.pem")
  SIG_KEY2="sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"${EPH2_X}\""
  rr_hdr=$(mktemp)
  rr_body=$(mktemp)
  curl -sS -D "$rr_hdr" -o "$rr_body" -X POST "${BASE}/register" \
    -H "Content-Type: application/json" \
    -H "Signature-Input: ${SIG_INPUT}" \
    -H "Signature: ${SIG}" \
    -H "Signature-Key: ${SIG_KEY2}" \
    -d "{\"stable_pub\": {\"kty\": \"OKP\", \"crv\": \"Ed25519\", \"x\": \"${STABLE_X}\"}, \"label\": \"Walkthrough device\"}"
  rr_code=$(http_code_from_headers "$rr_hdr")
  if [[ "$rr_code" != "200" ]]; then
    bad "re-register → HTTP ${rr_code} (expected 200)"
    exit 1
  fi
  ok "re-register → HTTP 200 (no approval needed)"
  local TOKEN2
  TOKEN2=$(python3 -c "import json,sys; print(json.load(open('${rr_body}')).get('agent_token',''))")
  local PAYLOAD_X2
  PAYLOAD_X2=$(printf '%s' "$TOKEN2" | python3 -c "
import sys, base64, json
raw = sys.stdin.read().strip().split('.')[1]
pad = 4 - len(raw) % 4
if pad < 4:
    raw += '=' * pad
p = json.loads(base64.urlsafe_b64decode(raw))
print((p.get('cnf') or {}).get('jwk', {}).get('x', ''))
")
  if [[ "$PAYLOAD_X2" == "$EPH2_X" ]]; then
    ok "immediate token cnf.jwk.x matches new ephemeral key"
  else
    bad "re-register token cnf mismatch"
    exit 1
  fi
  rm -f "$rr_hdr" "$rr_body"
  pause

  say "Step 8 — GET /person/registrations (pending list; may be empty)"
  local pr_hdr pr_body pr_code
  pr_hdr=$(mktemp)
  pr_body=$(mktemp)
  curl -sS -D "$pr_hdr" -o "$pr_body" "${BASE}/person/registrations" \
    -H "Authorization: Bearer ${PERSON_TOKEN}"
  pr_code=$(http_code_from_headers "$pr_hdr")
  rm -f "$pr_hdr"
  if [[ "$pr_code" != "200" ]]; then
    bad "GET /person/registrations → HTTP ${pr_code}"
    exit 1
  fi
  if have_jq; then jq . <"$pr_body" | sed 's/^/    /'; else sed 's/^/    /' "$pr_body"; fi
  rm -f "$pr_body"
  ok "GET /person/registrations → HTTP 200"
  pause

  say "Step 9 — GET /person/bindings (should list enrolled device)"
  local pb_hdr pb_body pb_code
  pb_hdr=$(mktemp)
  pb_body=$(mktemp)
  curl -sS -D "$pb_hdr" -o "$pb_body" "${BASE}/person/bindings" \
    -H "Authorization: Bearer ${PERSON_TOKEN}"
  pb_code=$(http_code_from_headers "$pb_hdr")
  rm -f "$pb_hdr"
  if [[ "$pb_code" != "200" ]]; then
    bad "GET /person/bindings → HTTP ${pb_code}"
    exit 1
  fi
  if have_jq; then jq . <"$pb_body" | sed 's/^/    /'; else sed 's/^/    /' "$pb_body"; fi
  ok "GET /person/bindings → HTTP 200"
  if python3 -c "
import json, sys
aid, path = sys.argv[1], sys.argv[2]
with open(path) as f:
    data = json.load(f)
ids = [b.get('agent_id', '') for b in data] if isinstance(data, list) else []
sys.exit(0 if aid in ids else 1)
" "$AGENT_ID" "$pb_body"; then
    ok "bindings list includes this walkthrough's agent_id"
  else
    bad "agent_id not found in bindings list (unexpected)"
    exit 1
  fi
  rm -f "$pb_body"
  pause

  say "Optional — POST /person/bindings/{agent_id}/revoke"
  if [[ "$AUTO" == "1" ]]; then
    sub "AUTO=1: skipping revoke (destructive). Run interactively to confirm revoke."
  else
    read -r -p "Revoke binding ${AGENT_ID}? [y/N] " ans
    if [[ "${ans:-}" =~ ^[Yy]$ ]]; then
      local enc
      enc=$(AGENT_ID="$AGENT_ID" python3 -c "import os, urllib.parse; print(urllib.parse.quote(os.environ['AGENT_ID'], safe=''))")
      local rv_hdr rv_code
      rv_hdr=$(mktemp)
      curl -sS -D "$rv_hdr" -o /dev/null -X POST \
        "${BASE}/person/bindings/${enc}/revoke" \
        -H "Authorization: Bearer ${PERSON_TOKEN}"
      rv_code=$(http_code_from_headers "$rv_hdr")
      rm -f "$rv_hdr"
      if [[ "$rv_code" == "200" ]]; then
        ok "revoke → HTTP 200"
      else
        bad "revoke → HTTP ${rv_code}"
      fi
    else
      sub "skipped revoke"
    fi
  fi

  say "Done — all steps completed."
}

main "$@"
