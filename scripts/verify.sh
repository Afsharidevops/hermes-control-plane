#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 -m compileall -q "$ROOT/control-plane/src" "$ROOT/router-gateway/src" "$ROOT/node-agent/src"
ROOT="$ROOT" python3 - <<'PY'
from pathlib import Path
import os
root=Path(os.environ['ROOT'])
for f in ['plan.md','README.md','docker-compose.yml','charts/hermes-control-plane/Chart.yaml']:
    p=root/f
    if not p.exists() or not p.read_text().strip():
        raise SystemExit(f'missing/empty: {p}')
print('foundation files: ok')
PY
if command -v docker >/dev/null 2>&1 && [[ -f "$ROOT/.env" ]]; then
  docker compose --project-directory "$ROOT" --env-file "$ROOT/.env" config >/dev/null
  echo "docker compose config: ok"
fi
if command -v helm >/dev/null 2>&1; then
  helm lint "$ROOT/charts/hermes-control-plane"
fi
