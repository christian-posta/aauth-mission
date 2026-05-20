#!/usr/bin/env bash
# Mission-aware Person Server demo — exercises Layer 1 (mission-aware /token) and Layer 2
# (approved-tools gating on /permission) end-to-end via curl.
#
# Walks through, in order:
#   §A  Approve a mission with an explicit ``approved_tools`` list
#   §B  /permission for a tool IN approved_tools           → 200 granted
#   §C  /permission for a tool OUTSIDE approved_tools      → 202 deferred → user APPROVES
#   §D  /permission for another tool OUTSIDE approved_tools → 202 deferred → user DENIES
#   §E  /token under the mission                            → 202 deferred (evaluator escalates),
#                                                            reason carried into consent context
#   §F  GET /missions/{s256} — print the full mission log
#
# Requires:
#   - Person Server with the keyword evaluator enabled:
#       AAUTH_PS_MISSION_EVALUATOR=keyword \
#       AAUTH_PS_ADMIN_TOKEN=mytoken \
#       AAUTH_PS_INSECURE_DEV=true \
#       uvicorn ps.http.app:app --host 127.0.0.1 --port 8765
#   - curl, and ideally jq (brew install jq)
#
# Usage:
#   chmod +x scripts/mission-demo.sh
#   ./scripts/mission-demo.sh
#   BASE_URL=http://127.0.0.1:8766 AGENT_ID=my-agent ./scripts/mission-demo.sh

set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8765}"
BASE_URL="${BASE_URL%/}"
AGENT_ID="${AGENT_ID:-mission-demo-agent}"
ADMIN_TOKEN="${ADMIN_TOKEN:-mytoken}"

have_jq() { command -v jq >/dev/null 2>&1; }

section() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$*"; }
step()    { printf '\n\033[1m%s\033[0m\n' "$*"; }
sub()     { printf '  %s\n' "$*"; }

print_req() {
  step "Request"
  sub "$1 $2"
  if [[ -n "${3:-}" ]]; then sub "Headers: ${3}"; fi
  if [[ -n "${4:-}" ]]; then
    sub "Body:"
    if have_jq && printf '%s' "$4" | jq -e . >/dev/null 2>&1; then
      printf '%s\n' "$4" | jq . | sed 's/^/    /'
    else
      printf '    %s\n' "$4"
    fi
  fi
}

print_res() {
  step "Response"
  sed 's/^/  /'
}

print_json() {
  local f=$1
  step "Response body"
  if have_jq; then jq . "$f" | sed 's/^/  /'; else sed 's/^/  /' <"$f"; fi
}

abs_url() {
  local p=$1
  if [[ "$p" == http://* || "$p" == https://* ]]; then printf '%s' "$p"; else printf '%s%s' "$BASE_URL" "$p"; fi
}

http_status_from_file() { head -1 "$1" | sed -n 's:^HTTP/[^ ]* \([0-9]*\).*:\1:p'; }

parse_field_curl_dump() {
  # $1 = file with `curl -i` output, $2 = header name (case-insensitive)
  grep -i "^$2:" "$1" | head -1 | sed "s/^[^:]*:[[:space:]]*//;s/\r$//"
}

require_evaluator_keyword() {
  step "Checking evaluator wiring at ${BASE_URL}"
  # No direct introspection endpoint — issue a quick probe to verify the demo path is wired.
  curl -sS "${BASE_URL}/.well-known/aauth-person.json" >/dev/null
  sub "Server reachable. If the demo's /token §E does not show evaluator_reason in §E.2, the"
  sub "server is not running with AAUTH_PS_MISSION_EVALUATOR=keyword."
}

main() {
  TMP=$(mktemp -d)
  trap 'rm -rf "${TMP:-}"' EXIT

  step "Mission demo — base=${BASE_URL} agent=${AGENT_ID}"
  if ! have_jq; then sub "(install jq for prettier JSON: brew install jq)"; fi
  require_evaluator_keyword

  ###############################
  section "§A Approve a mission"
  ###############################
  local body_m
  body_m=$(cat <<'JSON'
{
  "description": "# Plan a Tokyo trip\n\nResearch flights and hotels. Search the web freely. Do not: delete any existing bookings.",
  "tools": [{"name": "WebSearch", "description": "Search the web"}]
}
JSON
)
  print_req "POST" "${BASE_URL}/mission" "X-AAuth-Agent-Id: ${AGENT_ID}" "$body_m"
  curl -sS -D "${TMP}/m.h" -o "${TMP}/m.j" -X POST "${BASE_URL}/mission" \
    -H "Content-Type: application/json" -H "X-AAuth-Agent-Id: ${AGENT_ID}" -d "$body_m"
  step "Response headers"; sed 's/^/  /' "${TMP}/m.h"
  print_json "${TMP}/m.j"

  local hdr approver s256
  hdr=$(grep -i '^AAuth-Mission:' "${TMP}/m.h" | tr -d '\r')
  approver=$(printf '%s' "$hdr" | sed -n 's/.*approver="\([^"]*\)".*/\1/p')
  s256=$(printf     '%s' "$hdr" | sed -n 's/.*s256="\([^"]*\)".*/\1/p')
  sub "approver=${approver}"
  sub "s256=${s256}"

  #####################################################
  section "§B /permission — action IS in approved_tools"
  #####################################################
  local body_b
  body_b=$(printf '{"action":"WebSearch","description":"Search flights TYO","mission":{"approver":"%s","s256":"%s"}}' "$approver" "$s256")
  print_req "POST" "${BASE_URL}/permission" "X-AAuth-Agent-Id: ${AGENT_ID}" "$body_b"
  curl -sS -i -X POST "${BASE_URL}/permission" \
    -H "Content-Type: application/json" -H "X-AAuth-Agent-Id: ${AGENT_ID}" -d "$body_b" | print_res
  sub "Expect 200 with {\"permission\":\"granted\"} — auto-granted because WebSearch is in approved_tools."

  ###############################################################
  section "§C /permission — action OUTSIDE approved_tools (approve)"
  ###############################################################
  local body_c
  body_c=$(printf '{"action":"BookFlight","description":"Book TYO/JL062","parameters":{"flight":"JL062"},"mission":{"approver":"%s","s256":"%s"}}' "$approver" "$s256")
  print_req "POST" "${BASE_URL}/permission" "X-AAuth-Agent-Id: ${AGENT_ID}" "$body_c"
  curl -sS -i -X POST "${BASE_URL}/permission" \
    -H "Content-Type: application/json" -H "X-AAuth-Agent-Id: ${AGENT_ID}" -d "$body_c" >"${TMP}/c.i"
  sed 's/^/  /' "${TMP}/c.i"

  local c_status; c_status=$(http_status_from_file "${TMP}/c.i")
  [[ "$c_status" == "202" ]] || { sub "Expected 202, got ${c_status}"; exit 1; }

  # Strip CRLFs + extract body JSON from curl -i dump.
  sed -e 's/\r$//' "${TMP}/c.i" | awk 'p {print} /^$/ {p=1}' >"${TMP}/c.j"
  local c_pid c_code
  if have_jq; then c_pid=$(jq -r .pending_id "${TMP}/c.j"); c_code=$(jq -r .code "${TMP}/c.j"); fi
  sub "pending_id=${c_pid}  code=${c_code}"

  step "GET /consent?code=…  (what the user sees)"
  curl -sS "${BASE_URL}/consent?code=${c_code}" >"${TMP}/c.ctx"
  print_json "${TMP}/c.ctx"
  sub "Note the 'permission_action', 'permission_description', and 'permission_parameters' fields."

  step "User APPROVES (POST /consent/{pid}/decision)"
  curl -sS -i -X POST "${BASE_URL}/consent/${c_pid}/decision" \
    -H "Content-Type: application/json" -d '{"approved":true}' | print_res

  step "Agent polls GET /pending/{id} → terminal body"
  curl -sS -i "${BASE_URL}/pending/${c_pid}" -H "X-AAuth-Agent-Id: ${AGENT_ID}" | print_res
  sub "Expect 200 with {\"permission\":\"granted\"}."

  ############################################################
  section "§D /permission — action OUTSIDE approved_tools (deny)"
  ############################################################
  local body_d
  body_d=$(printf '{"action":"DeleteAccount","description":"Wipe profile","mission":{"approver":"%s","s256":"%s"}}' "$approver" "$s256")
  print_req "POST" "${BASE_URL}/permission" "X-AAuth-Agent-Id: ${AGENT_ID}" "$body_d"
  curl -sS -i -X POST "${BASE_URL}/permission" \
    -H "Content-Type: application/json" -H "X-AAuth-Agent-Id: ${AGENT_ID}" -d "$body_d" >"${TMP}/d.i"
  sed 's/^/  /' "${TMP}/d.i"
  sed -e 's/\r$//' "${TMP}/d.i" | awk 'p {print} /^$/ {p=1}' >"${TMP}/d.j"
  local d_pid; d_pid=$(jq -r .pending_id "${TMP}/d.j")

  step "User DENIES"
  curl -sS -i -X POST "${BASE_URL}/consent/${d_pid}/decision" \
    -H "Content-Type: application/json" -d '{"approved":false}' | print_res

  step "Agent polls → terminal body"
  curl -sS -i "${BASE_URL}/pending/${d_pid}" -H "X-AAuth-Agent-Id: ${AGENT_ID}" | print_res
  sub "Expect 200 with {\"permission\":\"denied\"} — note this is NOT 403; the user's decision is the result."

  #################################################################
  section "§E /token under mission — evaluator escalates with reason"
  #################################################################
  local body_e
  body_e=$(printf '{"resource_token":"fake-jwt","justification":"Need to search for flights","mission":{"approver":"%s","s256":"%s"}}' "$approver" "$s256")
  print_req "POST" "${BASE_URL}/token" "X-AAuth-Agent-Id: ${AGENT_ID}" "$body_e"
  curl -sS -i -X POST "${BASE_URL}/token" \
    -H "Content-Type: application/json" -H "X-AAuth-Agent-Id: ${AGENT_ID}" -d "$body_e" >"${TMP}/e.i"
  sed 's/^/  /' "${TMP}/e.i"
  sed -e 's/\r$//' "${TMP}/e.i" | awk 'p {print} /^$/ {p=1}' >"${TMP}/e.j"
  local e_code; e_code=$(jq -r .code "${TMP}/e.j")

  step "§E.2  GET /consent?code=…  — evaluator_reason should appear"
  curl -sS "${BASE_URL}/consent?code=${e_code}" >"${TMP}/e.ctx"
  print_json "${TMP}/e.ctx"
  if have_jq && jq -e .evaluator_reason "${TMP}/e.ctx" >/dev/null; then
    sub "✓ evaluator_reason present — Layer 1 is wired."
  else
    sub "✗ evaluator_reason MISSING — start the server with AAUTH_PS_MISSION_EVALUATOR=keyword."
  fi

  ########################################
  section "§F GET /missions/{s256} — full log"
  ########################################
  step "GET /missions/${s256}"
  curl -sS -H "Authorization: Bearer ${ADMIN_TOKEN}" "${BASE_URL}/missions/${s256}" >"${TMP}/log.json"
  print_json "${TMP}/log.json"
  sub "Inspect the 'log' array — you should see mission_approved + permission entries (granted, deferred, user-decided) +"
  sub "token_request entries with stage=evaluator carrying the decision and reason."

  step "Done."
}

main "$@"
