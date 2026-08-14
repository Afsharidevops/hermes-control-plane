# Hermes Control Plane

Hermes Control Plane is the next-generation foundation for the Hermes Linux Stack: a self-hosted, AI-assisted DevOps control plane designed for Docker/VM and Kubernetes deployment.

> Current version: **0.5.10-alpha.1**. This repository is a foundation release. It is not yet the production-complete DevOps management feature set described in `plan.md`.

## What is included now

- Hermes Smart Router / Operations Center foundation migrated from v0.5.9
- Hermes Execution Broker foundation migrated from v0.5.9
- runtime-selectable 9router / OmniRoute gateway
- Control Plane API foundation
- Node Agent foundation
- Docker Compose deployment
- Kubernetes Helm chart foundation
- Docker image build/push scripts
- CI validation
- v0.5.10 product and security roadmap

## Architecture

```text
Web / Telegram / API
        |
Hermes Control Plane
        |
    Smart Router
        |
  Router Gateway
    /       \
9router   OmniRoute

ChangeSet / policy / approval layer
        |
Broker or Node Agent
        |
Kubernetes / Helm / Docker / Swarm / SSH / Git
```

## Quick start — Docker

```bash
cp .env.example .env
./hermesctl init
./hermesctl up
./hermesctl status
```

The default provider is `nine-router`. Change it before startup:

```bash
./hermesctl router set omniroute
./hermesctl up
```

To run both router containers and switch the active upstream through the gateway:

```bash
HERMES_ENABLE_BOTH_ROUTERS=true ./hermesctl up
./hermesctl router set nine-router
./hermesctl router set omniroute
```

## Quick start — Kubernetes

```bash
helm upgrade --install hermes-control-plane ./charts/hermes-control-plane \
  --namespace hermes-system \
  --create-namespace
```

Choose OmniRoute:

```bash
helm upgrade --install hermes-control-plane ./charts/hermes-control-plane \
  --namespace hermes-system \
  --create-namespace \
  --set router.activeProvider=omniroute \
  --set routers.nineRouter.enabled=false \
  --set routers.omniroute.enabled=true
```

Review and replace all placeholder secrets before exposing any service.

## Router selection

Smart Router uses `router-gateway` as a stable OpenAI-compatible upstream. The gateway forwards requests to the active provider.

```bash
./hermesctl router list
./hermesctl router set nine-router
./hermesctl router set omniroute
```

The gateway management endpoint requires `ROUTER_GATEWAY_ADMIN_TOKEN`.

## Images

This repository builds these project-owned images:

- `hermes-control-plane-api`
- `hermes-control-plane-router-gateway`
- `hermes-control-plane-smart-router`
- `hermes-control-plane-execution-broker`
- `hermes-control-plane-node-agent`

9router, OmniRoute, and Hermes Agent are upstream images and are not rebuilt here.

Build locally:

```bash
IMAGE_NAMESPACE=yourdockerhub ./scripts/build-images.sh
```

Push multi-platform images:

```bash
IMAGE_NAMESPACE=yourdockerhub VERSION=0.5.10-alpha.1 ./scripts/push-images.sh
```

## Security status

Execution features are intentionally incomplete and should remain disabled for production until the ChangeSet, credential, approval and agent boundaries in `plan.md` are implemented and reviewed.

See `plan.md` and `SECURITY.md`.

## Docker image namespace isolation

This project deliberately uses Docker Hub repositories prefixed with `hermes-control-plane-` so it never overwrites images published by `hermes-linux-stack`. The project-owned images are:

- `hermes-control-plane-api`
- `hermes-control-plane-router-gateway`
- `hermes-control-plane-smart-router`
- `hermes-control-plane-execution-broker`
- `hermes-control-plane-node-agent`

The legacy repositories `hermes-smart-router` and `hermes-execution-broker` are reserved for `hermes-linux-stack` and must not be published by this project.
