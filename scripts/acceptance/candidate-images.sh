#!/usr/bin/env bash
set -euo pipefail
TAG="${1:-}"
NAMESPACE="${IMAGE_NAMESPACE:-afsharidevops}"
[[ "$TAG" =~ ^0\.5\.10(-rc\.[0-9]+)?-candidate\.[0-9a-f]{7,40}$ ]] || { echo "usage: $0 0.5.10-candidate.<git-sha>" >&2; exit 2; }
command -v docker >/dev/null || { echo "docker/buildx is required" >&2; exit 3; }
images=(
  hermes-control-plane-api
  hermes-control-plane-router-gateway
  hermes-control-plane-smart-router
  hermes-control-plane-execution-broker
  hermes-control-plane-kubernetes-broker
  hermes-control-plane-node-agent
)
for image in "${images[@]}"; do
  ref="$NAMESPACE/$image:$TAG"
  output="$(docker buildx imagetools inspect "$ref")"
  grep -q 'linux/amd64' <<<"$output" || { echo "$ref missing linux/amd64" >&2; exit 1; }
  grep -q 'linux/arm64' <<<"$output" || { echo "$ref missing linux/arm64" >&2; exit 1; }
  echo "[ok] $ref amd64+arm64"
done
