#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$ROOT/release-evidence"
{
  echo "Hermes Control Plane stable source gate"
  echo "version=$(cat "$ROOT/VERSION")"
  date -u +"utc=%Y-%m-%dT%H:%M:%SZ"
  "$ROOT/scripts/verify.sh"
  PYTHONPATH="$ROOT/smart-router/src" python3 -m pytest -q "$ROOT/smart-router/tests"
  python3 -m compileall -q "$ROOT/control-plane/src" "$ROOT/kubernetes-broker/src" "$ROOT/router-gateway/src" "$ROOT/node-agent/src"
  grep -q '^0.5.10$' "$ROOT/VERSION"
  grep -q 'appVersion: "0.5.10"' "$ROOT/charts/hermes-control-plane/Chart.yaml"
  echo "stable-source-gate: PASS"
} | tee "$ROOT/release-evidence/stable-source-gate.txt"
