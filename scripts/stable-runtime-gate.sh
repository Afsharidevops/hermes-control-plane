#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="${1:-}"
COMPOSE_URL="${2:-}"
KUBERNETES_URL="${3:-}"
[[ -n "$TAG" ]] || { echo "usage: $0 <0.5.11-candidate.sha> [compose-url kubernetes-url]" >&2; exit 2; }
"$ROOT/scripts/acceptance/candidate-images.sh" "$TAG"
if [[ -n "$COMPOSE_URL" || -n "$KUBERNETES_URL" ]]; then
  [[ -n "$COMPOSE_URL" && -n "$KUBERNETES_URL" ]] || { echo "provide both deployment URLs" >&2; exit 2; }
  python3 "$ROOT/scripts/acceptance/api-equivalence.py" "$COMPOSE_URL" "$KUBERNETES_URL"
  python3 "$ROOT/scripts/acceptance/migration-acceptance.py" "$COMPOSE_URL" "$KUBERNETES_URL"
fi
echo "stable-runtime-gate: PASS"
