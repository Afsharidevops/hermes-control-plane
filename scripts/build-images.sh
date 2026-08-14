#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS="${IMAGE_NAMESPACE:?Set IMAGE_NAMESPACE to your Docker Hub username/organization}"
VERSION="${VERSION:-$(cat "$ROOT/VERSION")}" 
for spec in \
  "hermes-control-plane-api:control-plane" \
  "hermes-control-plane-router-gateway:router-gateway" \
  "hermes-control-plane-smart-router:smart-router" \
  "hermes-control-plane-execution-broker:execution-broker" \
  "hermes-control-plane-node-agent:node-agent"; do
  name="${spec%%:*}"; dir="${spec#*:}"
  echo "==> building ${NS}/${name}:${VERSION}"
  docker build -t "${NS}/${name}:${VERSION}" -t "${NS}/${name}:dev" "$ROOT/$dir"
done
