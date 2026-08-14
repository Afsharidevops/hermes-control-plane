#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 -m compileall -q "$ROOT/control-plane/src" "$ROOT/router-gateway/src" "$ROOT/node-agent/src" "$ROOT/kubernetes-broker/src"
ROOT="$ROOT" python3 - <<'PY'
from pathlib import Path
import os
root=Path(os.environ['ROOT'])
for f in ['plan.md','README.md','HANDOVER.md','docker-compose.yml','charts/hermes-control-plane/Chart.yaml','docs/ALPHA2.md','docs/BETA1.md']:
    p=root/f
    if not p.exists() or not p.read_text().strip():
        raise SystemExit(f'missing/empty: {p}')
compose=(root/'docker-compose.yml').read_text()
ctl=(root/'hermesctl').read_text()
workflow=(root/'.github/workflows/validate.yml').read_text()
for marker in [
    './plugins/control-plane-chatops:/opt/data/plugins/control-plane-chatops:ro',
    'TELEGRAM_BOT_TOKEN:',
    'TELEGRAM_ALLOWED_USERS:',
    'HERMES_KUBERNETES_BROKER_UID',
]:
    if marker not in compose:
        raise SystemExit(f'missing compose wiring: {marker}')
if 'plugins enable control-plane-chatops' not in ctl:
    raise SystemExit('hermesctl does not auto-enable ChatOps plugin')
if '--entrypoint /opt/hermes/.venv/bin/hermes' not in ctl:
    raise SystemExit('Hermes plugin CLI helper does not bypass gateway entrypoint')
if "'dev/**'" not in workflow:
    raise SystemExit('validate workflow does not cover dev/** pushes')
print('foundation files: ok')
print('bot/credential wiring: ok')
PY
if PYTHONPATH="$ROOT/control-plane/src" python3 - <<'PY' >/dev/null 2>&1
import fastapi, httpx, pytest
PY
then
  PYTHONPATH="$ROOT/control-plane/src" python3 -m pytest -q "$ROOT/control-plane/tests"
  if PYTHONPATH="$ROOT/kubernetes-broker/src" python3 - <<'PY2' >/dev/null 2>&1
import yaml
PY2
  then
    PYTHONPATH="$ROOT/kubernetes-broker/src" python3 -m pytest -q "$ROOT/kubernetes-broker/tests"
  else
    echo "kubernetes-broker tests: skipped locally (install kubernetes-broker/requirements-dev.txt); CI runs them"
  fi
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
