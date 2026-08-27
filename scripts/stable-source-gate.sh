#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$ROOT/release-evidence"
{
  echo "Hermes Control Plane stable source gate"
  echo "version=$(cat "$ROOT/VERSION")"
  date -u +"utc=%Y-%m-%dT%H:%M:%SZ"
  grep -q '^0.5.11$' "$ROOT/VERSION"
  grep -q 'appVersion: "0.5.11"' "$ROOT/charts/hermes-control-plane/Chart.yaml"
  bash -n "$ROOT/hermesctl" "$ROOT/scripts/stable-runtime-gate.sh" "$ROOT/scripts/acceptance/candidate-images.sh"
  python3 "$ROOT/scripts/acceptance/source-security-gate.py"
  "$ROOT/scripts/verify.sh"
  PYTHONPATH="$ROOT/execution-broker/src" python3 -m pytest -q "$ROOT/execution-broker/tests"
  PYTHONPATH="$ROOT/smart-router/src" python3 -m pytest -q "$ROOT/smart-router/tests"
  python3 -m compileall -q "$ROOT/control-plane/src" "$ROOT/kubernetes-broker/src" "$ROOT/router-gateway/src" "$ROOT/node-agent/src"
  echo "stable-source-gate: PASS"
} 2>&1 | tee "$ROOT/release-evidence/stable-source-gate.txt"
