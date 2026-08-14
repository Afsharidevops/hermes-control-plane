# Hermes Control Plane

Hermes Control Plane is a self-hosted, AI-assisted DevOps control plane designed to run on a Docker/VM installation or Kubernetes while keeping privileged credentials and infrastructure execution outside the LLM trust boundary.

> Current version: **0.5.10-alpha.2 — Management + Safety Core**. Privileged Kubernetes/Docker/Git/SSH mutation remains disabled until the beta adapters are bound to this release's ChangeSet/approval contract.

## What is included

Foundation:

- Hermes Smart Router / Operations Center foundation migrated from v0.5.9
- Hermes Execution Broker foundation migrated from v0.5.9
- runtime-selectable 9router / OmniRoute gateway
- Node Agent foundation
- Docker Compose deployment
- Kubernetes Helm chart
- automatic multi-architecture Docker Hub publishing from GitHub Actions

Alpha.2 management/safety core:

- Environment Registry
- Integration Registry
- Target Registry
- credential references (metadata only; no raw secret values)
- integration HTTP/HTTPS health-test foundation
- starter management UI at `/ui`
- immutable canonical ChangeSet plans with SHA-256 hashes
- automatic risk classification
- preview/state management
- exact-hash approval binding
- HIGH/CRITICAL requester self-approval protection
- expiry and audit events
- alpha.1 SQLite migration/backfill

See `docs/ALPHA2.md`, `plan.md`, `SECURITY.md`, and `HANDOVER.md`.

## Architecture

```text
Web / Telegram / API
        |
Hermes Control Plane
  registries / ChangeSets / risk / audit
        |
    Smart Router
        |
  Router Gateway
    /       \
9router   OmniRoute

approved ChangeSet (beta+)
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

Open the alpha.2 management UI locally:

```text
http://127.0.0.1:8800/ui
```

The default provider is `nine-router`. Switch at runtime:

```bash
./hermesctl router set omniroute
./hermesctl router set nine-router
./hermesctl router list
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

## CI / Docker Hub

The repository uses these GitHub settings:

- Actions variable: `DOCKERHUB_USERNAME`
- Actions secret: `DOCKERHUB_TOKEN`

Pull requests build but do not push. A push to `main` publishes `:edge` and `:sha-...`. A version tag such as `v0.5.10-alpha.2` publishes `:0.5.10-alpha.2`. Only a stable tag such as `v0.5.10` publishes `:latest`.

Project-owned Docker Hub repositories are isolated from `hermes-linux-stack`:

- `hermes-control-plane-api`
- `hermes-control-plane-router-gateway`
- `hermes-control-plane-smart-router`
- `hermes-control-plane-execution-broker`
- `hermes-control-plane-node-agent`

9router, OmniRoute, and Hermes Agent are upstream images and are not rebuilt here.

Manual fallback build/publish remains available:

```bash
IMAGE_NAMESPACE=afsharidevops VERSION=0.5.10-alpha.2 ./scripts/push-images.sh
```

## Verify

```bash
./scripts/verify.sh
```

CI additionally runs the alpha.2 Control Plane tests, Compose validation, and Helm lint.

## Security status

The Control Plane API does not store raw credential material and has no privileged execute endpoint in alpha.2. Read `SECURITY.md` before exposing the stack or building beta adapters.
