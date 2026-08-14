#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS="${IMAGE_NAMESPACE:?Set IMAGE_NAMESPACE to your Docker Hub username/organization}"
VERSION="${VERSION:-$(cat "$ROOT/VERSION")}" 
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
BUILDER="${BUILDX_BUILDER:-hermes-builder}"
if ! docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
  docker buildx create --name "$BUILDER" --use
else
  docker buildx use "$BUILDER"
fi
docker buildx inspect --bootstrap >/dev/null
for spec in \
  "hermes-control-plane-api:control-plane" \
  "hermes-control-plane-router-gateway:router-gateway" \
  "hermes-control-plane-smart-router:smart-router" \
  "hermes-control-plane-execution-broker:execution-broker" \
  "hermes-control-plane-node-agent:node-agent"; do
  name="${spec%%:*}"; dir="${spec#*:}"
  tags=(-t "${NS}/${name}:${VERSION}")
  # Keep prereleases away from :latest. Stable x.y.z versions may update latest.
  if [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    tags+=(-t "${NS}/${name}:latest")
  fi
  echo "==> building/pushing ${NS}/${name}:${VERSION} (${PLATFORMS})"
  docker buildx build \
    --platform "$PLATFORMS" \
    --pull \
    --provenance=true \
    --sbom=true \
    "${tags[@]}" \
    --push \
    "$ROOT/$dir"
done
