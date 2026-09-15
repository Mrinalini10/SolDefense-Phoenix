#!/usr/bin/env bash
# SolDefense — full initialisation script
# Waits for Exasol to be ready, then delegates to init_all.py which applies
# all SQL migrations in the correct dependency order.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PY="python3"
if [ -f "$ROOT/venv/bin/python" ]; then
  PY="$ROOT/venv/bin/python"
fi

echo "Waiting for Exasol to accept connections..."
until "$PY" -c "
import pyexasol, ssl, os
from dotenv import load_dotenv
load_dotenv()
host = os.getenv('EXASOL_HOST', 'localhost:8563')
user = os.getenv('SYS_USER', 'sys')
pw   = os.getenv('SYS_PW', 'exasol')
pyexasol.connect(dsn=host, user=user, password=pw,
                 websocket_sslopt={'cert_reqs': ssl.CERT_NONE}).close()
" 2>/dev/null; do
  echo "  ... not ready yet, retrying in 5 s"
  sleep 5
done

echo "Exasol is ready. Applying migrations via init_all.py ..."
"$PY" scripts/init_all.py

echo "Done. Bring up proxy + scheduler with: docker compose up proxy scheduler"
