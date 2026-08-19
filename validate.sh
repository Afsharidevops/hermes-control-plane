#!/usr/bin/env bash
set -euo pipefail

ROOT="${HERMES_REPO:-${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}}"
cd "$ROOT"

[[ "$(cat VERSION)" == "0.5.11-dev.3" ]] || { echo "VERSION is not 0.5.11-dev.3" >&2; exit 2; }

python3 -m compileall -q control-plane/src credential-service/src kubernetes-broker/src router-gateway/src node-agent/src execution-broker/src smart-router/src scripts/acceptance
python3 scripts/acceptance/dev3-source-security-gate.py
python3 scripts/acceptance/dev3-config-static-gate.py

echo "control-plane tests:"
PYTHONPATH=control-plane/src python3 -m pytest -q control-plane/tests
echo "credential-service tests:"
PYTHONPATH=credential-service/src python3 -m pytest -q credential-service/tests
echo "kubernetes-broker tests:"
PYTHONPATH=kubernetes-broker/src python3 -m pytest -q kubernetes-broker/tests
echo "execution-broker tests:"
PYTHONPATH=execution-broker/src python3 -m pytest -q execution-broker/tests
echo "smart-router tests:"
PYTHONPATH=smart-router/src python3 -m pytest -q smart-router/tests

bash -n hermesctl apply.sh validate.sh push.sh scripts/*.sh

if command -v docker >/dev/null 2>&1; then
  tmp_env="$(mktemp)"
  trap 'rm -f "$tmp_env"' EXIT
  cp .env.example "$tmp_env"
  sed -i 's/CHANGE_ME/0123456789abcdef0123456789abcdef0123456789abcdef/g' "$tmp_env"
  docker compose --env-file "$tmp_env" config >/dev/null
  echo "docker compose config: PASS"
else
  echo "docker compose config: SKIP (docker unavailable)"
fi

if command -v helm >/dev/null 2>&1; then
  helm lint charts/hermes-control-plane
else
  echo "helm lint: SKIP (helm unavailable)"
fi

# Optional non-publishing local image compilation. Production publication remains CI-owned.
if [[ "${HERMES_VALIDATE_LOCAL_IMAGES:-0}" == "1" ]]; then
  command -v docker >/dev/null 2>&1 || { echo "docker is required for HERMES_VALIDATE_LOCAL_IMAGES=1" >&2; exit 6; }
  for context in control-plane credential-service router-gateway smart-router execution-broker kubernetes-broker node-agent; do
    docker build --pull=false -t "hermes-validation/${context}:0.5.11-dev.3" "$context"
  done
fi

echo "Hermes 0.5.11-dev.3 validation: PASS"
