#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 -m compileall -q "$ROOT/control-plane/src" "$ROOT/router-gateway/src" "$ROOT/node-agent/src"
ROOT="$ROOT" python3 - <<'PY'
from pathlib import Path
import os
root=Path(os.environ['ROOT'])
for f in ['plan.md','README.md','HANDOVER.md','docker-compose.yml','charts/hermes-control-plane/Chart.yaml','docs/ALPHA2.md']:
    p=root/f
    if not p.exists() or not p.read_text().strip():
        raise SystemExit(f'missing/empty: {p}')
print('foundation files: ok')
PY
if PYTHONPATH="$ROOT/control-plane/src" python3 - <<'PY' >/dev/null 2>&1
import fastapi, httpx, pytest
PY
then
  PYTHONPATH="$ROOT/control-plane/src" python3 -m pytest -q "$ROOT/control-plane/tests"
else
  echo "control-plane tests: skipped locally (install control-plane/requirements-dev.txt); CI runs them"
fi
if command -v docker >/dev/null 2>&1 && [[ -f "$ROOT/.env" ]]; then
  docker compose --project-directory "$ROOT" --env-file "$ROOT/.env" config >/dev/null
  echo "docker compose config: ok"
fi
if command -v helm >/dev/null 2>&1; then
  helm lint "$ROOT/charts/hermes-control-plane"
fi
