#!/usr/bin/env bash
# Run the HWK sample client (Python + aauth). Requires AAUTH_PS_INSECURE_DEV=false.
# By default: POST /mission (demo description) then POST /token with mission; use --no-mission for token only.
# Optional: --mission-description, --permission-action, --audit, --complete-mission.
#
# Works against both the unified portal (portal.http.app) and the standalone Person Server.
# PS routes are at the same paths in both.
#
#   # Unified portal (port 8765):
#   AAUTH_PS_INSECURE_DEV=false AAUTH_AS_INSECURE_DEV=false \
#     AAUTH_PS_ADMIN_TOKEN=mytoken AAUTH_AS_PERSON_TOKEN=mytoken \
#     uvicorn portal.http.app:app --host 127.0.0.1 --port 8765
#   ./scripts/hwk-ps-client.sh --base-url http://127.0.0.1:8765
#
#   # Standalone PS only (port 8766):
#   AAUTH_PS_INSECURE_DEV=false uvicorn ps.http.app:app --host 127.0.0.1 --port 8766
#   ./scripts/hwk-ps-client.sh --base-url http://localhost:8766 --mission-description "# Demo" --audit
#
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${ROOT}/.venv/bin/python"
if [[ ! -x "$PY" ]]; then
  PY="${PYTHON:-python3}"
fi
exec "$PY" "${ROOT}/scripts/_hwk_ps_client.py" "$@"
