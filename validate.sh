#!/usr/bin/env bash
set -euo pipefail

ROOT="${HERMES_REPO:-${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}}"
cd "$ROOT"

[[ "$(cat VERSION)" == "0.5.11-dev.5" ]] || { echo "VERSION is not 0.5.11-dev.5" >&2; exit 2; }

# Prefer an explicitly selected interpreter, then an existing project virtualenv,
# then the ambient python3. The validator requires pytest; do not silently use a
# Python interpreter that cannot run the repository test suites.
select_python() {
  local candidate
  if [[ -n "${HERMES_PYTHON:-}" ]]; then
    candidate="$HERMES_PYTHON"
    if [[ -x "$candidate" ]] || command -v "$candidate" >/dev/null 2>&1; then
      if "$candidate" -c 'import pytest' >/dev/null 2>&1; then
        printf '%s\n' "$candidate"
        return 0
      fi
    fi
    echo "HERMES_PYTHON cannot import pytest: $candidate" >&2
    return 1
  fi

  for candidate in \
    "$ROOT/.venv-dev5/bin/python" \
    "$ROOT/.venv-dev3/bin/python" \
    "$ROOT/.venv-dev2/bin/python" \
    "$ROOT/.venv/bin/python" \
    python3; do
    if [[ "$candidate" == */* ]]; then
      [[ -x "$candidate" ]] || continue
    else
      command -v "$candidate" >/dev/null 2>&1 || continue
    fi
    if "$candidate" -c 'import pytest' >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  cat >&2 <<'MSG'
No usable Python interpreter with pytest was found.
Create/refresh a repository virtualenv, for example:
  python3 -m venv .venv-dev5
  .venv-dev5/bin/python -m pip install -U pip pytest
  for req in control-plane/requirements.txt credential-service/requirements.txt \
    kubernetes-broker/requirements.txt router-gateway/requirements.txt node-agent/requirements.txt \
    smart-router/requirements.txt smart-router/requirements-dev.txt; do
    [ ! -f "$req" ] || .venv-dev5/bin/python -m pip install -r "$req"
  done
Then rerun ./validate.sh, or set HERMES_PYTHON=/path/to/python.
MSG
  return 1
}

PYTHON_BIN="$(select_python)" || exit 3
echo "validation python: $PYTHON_BIN"

"$PYTHON_BIN" -m compileall -q control-plane/src credential-service/src kubernetes-broker/src router-gateway/src node-agent/src execution-broker/src smart-router/src scripts/acceptance
"$PYTHON_BIN" scripts/acceptance/dev5-source-security-gate.py
"$PYTHON_BIN" scripts/acceptance/dev5-config-static-gate.py

echo "control-plane tests:"
PYTHONPATH=control-plane/src "$PYTHON_BIN" -m pytest -q control-plane/tests
echo "credential-service tests:"
PYTHONPATH=credential-service/src "$PYTHON_BIN" -m pytest -q credential-service/tests
echo "kubernetes-broker tests:"
PYTHONPATH=kubernetes-broker/src "$PYTHON_BIN" -m pytest -q kubernetes-broker/tests
echo "execution-broker tests:"
PYTHONPATH=execution-broker/src "$PYTHON_BIN" -m pytest -q execution-broker/tests
echo "smart-router tests:"
PYTHONPATH=smart-router/src "$PYTHON_BIN" -m pytest -q smart-router/tests

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
    docker build --pull=false -t "hermes-validation/${context}:0.5.11-dev.5" "$context"
  done
fi

echo "Hermes 0.5.11-dev.5 validation: PASS"
