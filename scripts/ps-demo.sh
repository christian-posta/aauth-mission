#!/usr/bin/env bash
# Exercise Person Server REST endpoints against a running server (default: http://127.0.0.1:8765).
#
# Works against both the unified portal (portal.http.app) and the standalone Person Server
# (ps.http.app) — PS routes are at the same paths in both.
#
# Usage:
#   chmod +x scripts/ps-demo.sh
#   ./scripts/ps-demo.sh                              # unified portal on port 8765
#   BASE_URL=http://127.0.0.1:8766 ./scripts/ps-demo.sh  # standalone PS on different port
#   BASE_URL=http://127.0.0.1:8080 AGENT_ID=my-agent ./scripts/ps-demo.sh
#
# Start the server first, e.g.:
#   # Unified portal (recommended):
#   AAUTH_PS_ADMIN_TOKEN=mytoken AAUTH_AS_PERSON_TOKEN=mytoken \
#     AAUTH_PS_INSECURE_DEV=true AAUTH_AS_INSECURE_DEV=true \
#     uvicorn portal.http.app:app --host 127.0.0.1 --port 8765
#
#   # Standalone PS only:
#   uvicorn ps.http.app:app --host 127.0.0.1 --port 8766

set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8765}"
BASE_URL="${BASE_URL%/}"
AGENT_ID="${AGENT_ID:-demo-agent}"

have_jq() { command -v jq >/dev/null 2>&1; }

say() {
  printf '\n\033[1m%s\033[0m\n' "$*"
}

sub() { printf '  %s\n' "$*"; }

print_req() {
  say "Request"
  sub "$1 $2"
  if [[ -n "${3:-}" ]]; then
    sub "Headers: ${3}"
  fi
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
  say "Response"
  sed 's/^/  /'
}

abs_url() {
  local path_or_url=$1
  if [[ "$path_or_url" == http://* || "$path_or_url" == https://* ]]; then
    printf '%s' "$path_or_url"
  else
    printf '%s%s' "$BASE_URL" "$path_or_url"
  fi
}

http_status_from_file() {
  head -1 "$1" | sed -n 's:^HTTP/[^ ]* \([0-9]*\).*:\1:p'
}

parse_s256_from_headers() {
  # stdin: raw response headers; extract s256 from AAuth-Mission
  grep -i '^AAuth-Mission:' | head -1 | sed -n 's/.*s256="\([^"]*\)".*/\1/p'
}

main() {
  PS_DEMO_TMPDIR=$(mktemp -d)
  trap 'rm -rf "${PS_DEMO_TMPDIR:-}"' EXIT

  say "Person Server demo — target ${BASE_URL} (agent: ${AGENT_ID})"
  if ! have_jq; then
    sub "(install jq for prettier JSON: brew install jq)"
  fi

  # --- Well-known (SPEC: aauth-person.json) ---
  print_req "GET" "${BASE_URL}/.well-known/aauth-person.json"
  curl -sS -i "${BASE_URL}/.well-known/aauth-person.json" | print_res

  # --- Mission (description + tools) ---
  local body_mission
  body_mission='{"description":"# Demo mission\n\nManual script exercise.","tools":[{"name":"WebSearch","description":"Search the web"}]}'
  print_req "POST" "${BASE_URL}/mission" "X-AAuth-Agent-Id: ${AGENT_ID}" "$body_mission"
  local mission_hdr="${PS_DEMO_TMPDIR}/mission.headers"
  curl -sS -D "$mission_hdr" -o "${PS_DEMO_TMPDIR}/mission.json" -X POST "${BASE_URL}/mission" \
    -H "Content-Type: application/json" \
    -H "X-AAuth-Agent-Id: ${AGENT_ID}" \
    -d "$body_mission"
  say "Response"
  sed 's/^/  /' "$mission_hdr"
  if have_jq; then
    jq . "${PS_DEMO_TMPDIR}/mission.json" | sed 's/^/  /'
  else
    sed 's/^/  /' "${PS_DEMO_TMPDIR}/mission.json"
  fi

  local approver s256 hdr_line
  hdr_line=$(grep -i '^AAuth-Mission:' "$mission_hdr" | tr -d '\r' || true)
  approver=$(printf '%s' "$hdr_line" | sed -n 's/.*approver="\([^"]*\)".*/\1/p')
  s256=$(printf '%s' "$hdr_line" | sed -n 's/.*s256="\([^"]*\)".*/\1/p')
  say "Extracted approver=${approver}"
  say "Extracted s256=${s256}"

  local mission_json
  mission_json=$(cat "${PS_DEMO_TMPDIR}/mission.json")
  local aauth_hdr
  aauth_hdr="AAuth-Mission: approver=\"${approver}\"; s256=\"${s256}\""

  # --- Permission (optional mission) ---
  local body_perm
  body_perm=$(printf '{"action":"WebSearch","description":"Search for demo","mission":{"approver":"%s","s256":"%s"}}' "$approver" "$s256")
  print_req "POST" "${BASE_URL}/permission" "X-AAuth-Agent-Id: ${AGENT_ID}" "$body_perm"
  curl -sS -i -X POST "${BASE_URL}/permission" \
    -H "Content-Type: application/json" \
    -H "X-AAuth-Agent-Id: ${AGENT_ID}" \
    -d "$body_perm" | print_res

  # --- Audit ---
  local body_audit
  body_audit=$(printf '{"mission":{"approver":"%s","s256":"%s"},"action":"WebSearch","description":"Ran search","result":{"n":1}}' "$approver" "$s256")
  print_req "POST" "${BASE_URL}/audit" "X-AAuth-Agent-Id: ${AGENT_ID}" "$body_audit"
  curl -sS -i -X POST "${BASE_URL}/audit" \
    -H "Content-Type: application/json" \
    -H "X-AAuth-Agent-Id: ${AGENT_ID}" \
    -d "$body_audit" | print_res

  # --- Token → deferred (with AAuth-Mission header) ---
  local body_token
  body_token='{"resource_token":"aa-resource.demo-token","justification":"Demo access"}'
  print_req "POST" "${BASE_URL}/token" "X-AAuth-Agent-Id: ${AGENT_ID}; ${aauth_hdr}" "$body_token"

  local full="${PS_DEMO_TMPDIR}/token.i"
  curl -sS -i -X POST "${BASE_URL}/token" \
    -H "Content-Type: application/json" \
    -H "X-AAuth-Agent-Id: ${AGENT_ID}" \
    -H "$aauth_hdr" \
    -d "$body_token" >"$full"

  local HTTP_STATUS
  HTTP_STATUS=$(http_status_from_file "$full")
  say "Response"
  sed 's/^/  /' <"$full"

  if [[ "$HTTP_STATUS" != "202" ]]; then
    say "Expected 202 from /token (ensure server has AAUTH_PS_AUTO_APPROVE_TOKEN unset/false). Skipping consent + DELETE demos."
    say "Done."
    exit 0
  fi

  local loc
  loc=$(grep -i '^Location:' "$full" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//;s/\r$//')
  local pending_url
  pending_url=$(abs_url "$loc")

  local req_line
  req_line=$(grep -i '^AAuth-Requirement:' "$full" | head -1 | sed 's/\r$//' || true)
  local code_val
  code_val=$(printf '%s' "$req_line" | grep -oE 'code="[^"]*"' | head -1 | sed 's/^code="//;s/"$//' || true)

  if [[ -z "$code_val" ]]; then
    say "Could not parse interaction code from AAuth-Requirement. Line was:"
    sub "${req_line:-<missing>}"
    exit 1
  fi

  say "Extracted Location (pending URL): ${pending_url}"
  say "Extracted interaction code: ${code_val}"

  # --- Consent context (single GET; interaction code is single-use) ---
  local pending_json="${PS_DEMO_TMPDIR}/interaction.json"
  print_req "GET" "${BASE_URL}/consent?code=${code_val}"
  curl -sS "${BASE_URL}/consent?code=${code_val}" >"$pending_json"
  say "Response"
  if have_jq; then
    jq . "$pending_json" | sed 's/^/  /'
  else
    sed 's/^/  /' <"$pending_json"
  fi

  local pid
  if have_jq; then
    pid=$(jq -r '.pending_id' "$pending_json")
  else
    pid=$(grep -oE '"pending_id"[[:space:]]*:[[:space:]]*"[^"]*"' "$pending_json" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
  fi
  if [[ -z "$pid" || "$pid" == "null" ]]; then
    say "Could not parse pending_id from consent JSON"
    cat "$pending_json"
    exit 1
  fi

  # --- User approves ---
  local body_dec='{"approved":true}'
  print_req "POST" "${BASE_URL}/consent/${pid}/decision" "Content-Type: application/json" "$body_dec"
  curl -sS -i -X POST "${BASE_URL}/consent/${pid}/decision" \
    -H "Content-Type: application/json" \
    -d "$body_dec" | print_res

  # --- Poll pending → auth token ---
  print_req "GET" "$pending_url" "X-AAuth-Agent-Id: ${AGENT_ID} (polling after consent)"
  curl -sS -i "$pending_url" -H "X-AAuth-Agent-Id: ${AGENT_ID}" | print_res

  # --- Cancel demo (second token, then DELETE) ---
  say "Second token request, then DELETE pending (expect 410 on next GET)"
  curl -sS -i -X POST "${BASE_URL}/token" \
    -H "Content-Type: application/json" \
    -H "X-AAuth-Agent-Id: ${AGENT_ID}" \
    -d '{"resource_token":"aa-resource.cancel-demo"}' >"${PS_DEMO_TMPDIR}/t2.i"

  say "Response"
  sed 's/^/  /' <"${PS_DEMO_TMPDIR}/t2.i"

  loc=$(grep -i '^Location:' "${PS_DEMO_TMPDIR}/t2.i" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//;s/\r$//')
  pending_url=$(abs_url "$loc")

  print_req "DELETE" "$pending_url" "X-AAuth-Agent-Id: ${AGENT_ID}"
  curl -sS -i -X DELETE "$pending_url" \
    -H "X-AAuth-Agent-Id: ${AGENT_ID}" | print_res

  print_req "GET" "$pending_url" "X-AAuth-Agent-Id: ${AGENT_ID} (expect 410 Gone)"
  curl -sS -i "$pending_url" -H "X-AAuth-Agent-Id: ${AGENT_ID}" | print_res

  say "Done."
}

main "$@"
