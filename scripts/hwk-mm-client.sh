#!/usr/bin/env bash
# Run the HWK sample client (Python + aauth). Requires MM with INSECURE_DEV=false.
#
#   AAUTH_MM_INSECURE_DEV=false uvicorn mm.http.app:app --host 127.0.0.1 --port 8000
#   ./scripts/hwk-mm-client.sh
#   ./scripts/hwk-mm-client.sh --base-url http://localhost:8000 --resource-token my-jwt
#
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${ROOT}/.venv/bin/python"
if [[ ! -x "$PY" ]]; then
  PY="${PYTHON:-python3}"
fi
exec "$PY" "${ROOT}/scripts/hwk_mm_client.py" "$@"
