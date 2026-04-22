#!/usr/bin/env bash
# Run the HWK sample client (Python + aauth). Requires Person Server with INSECURE_DEV=false.
# By default: POST /mission (demo description) then POST /token with mission; use --no-mission for token only.
# Optional: --mission-description, --permission-action, --audit, --complete-mission.
#
#   AAUTH_PS_INSECURE_DEV=false uvicorn ps.http.app:app --host 127.0.0.1 --port 8765
#   ./scripts/hwk-ps-client.sh
#   ./scripts/hwk-ps-client.sh --base-url http://localhost:8765 --mission-description "# Demo" --audit
#
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${ROOT}/.venv/bin/python"
if [[ ! -x "$PY" ]]; then
  PY="${PYTHON:-python3}"
fi
exec "$PY" "${ROOT}/scripts/_hwk_ps_client.py" "$@"
