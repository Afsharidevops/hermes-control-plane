# Hermes Control Plane

Hermes Control Plane is a self-hosted, AI-assisted DevOps control plane designed to run on a Docker/VM installation or Kubernetes while keeping privileged credentials and infrastructure execution outside the LLM trust boundary.

> **0.5.10 stable candidate:** the checkpoint hardening is implemented locally. Do not create the public `v0.5.10` tag until `docs/STABLE-0.5.10-ACCEPTANCE.md` passes on the exact candidate commit. Kubernetes/Helm mutations remain bot-only, policy-generation-bound, exact-hash approved, broker-executed, and disabled by default.

## What is included

Foundation:

- Hermes Smart Router / Operations Center foundation migrated from v0.5.9
- Hermes Execution Broker foundation migrated from v0.5.9
- runtime-selectable 9router / OmniRoute gateway
- Node Agent foundation
- Docker Compose deployment
- Kubernetes Helm chart
- automatic multi-architecture Docker Hub publishing from GitHub Actions

Alpha.2 management/safety core (retained):

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

Beta.1 work currently includes:

- dedicated Kubernetes Broker with target-aware kubectl 1.33-1.36 client selection and Helm 4.x tooling
- Kubernetes discovery and server-side manifest dry-run/diff
- Helm install/upgrade dry-run and rollback planning
- kubeconfig reference + local file fingerprint boundary for Docker/VM
- ChangeSet target snapshots and drift invalidation
- signed short-lived exact-plan execution tickets
- Kubernetes/Helm execution opt-in (off by default)
- Kubernetes observability/configuration views; infrastructure mutation controls are intentionally absent from the UI
- bot-only Kubernetes/Helm ChangeSet authorization with separate Approval Bot identity
- Hermes `control-plane-chatops` plugin restricted to allow-listed interactive Telegram users
- readiness-aware `hermesctl execution` and `wait` helpers
- `hermesctl kubeconfig`, `version`, and `upgrade` commands

See `docs/BETA1.md`, `docs/ALPHA2.md`, `plan.md`, `SECURITY.md`, and `HANDOVER.md`.

## Architecture

```text
Web UI (configure/observe)        Hermes Telegram Bot (mutations)
           |                                 |
           +----------> Hermes Control Plane <---------- Approval Bot
                         registries / ChangeSets
                         risk / exact-hash approval / audit
                                   |
                         signed one-time execution ticket
                                   |
                            Broker or Node Agent
                                   |
                   Kubernetes / Helm / Docker / Swarm / SSH / Git

Hermes -> Smart Router -> Router Gateway -> 9router / OmniRoute
```

## Quick start — Docker

```bash
cp .env.example .env
./hermesctl init
./hermesctl up
./hermesctl status
```

Open the Operations Center locally:

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

## Kubernetes target bootstrap on Docker/VM

After the stack is running, import kubeconfig material locally without sending it through the Control Plane API:

```bash
./hermesctl kubeconfig import production ~/.kube/config
./hermesctl kubeconfig list
```

Create the Kubernetes target in `/ui`, then use **Discover** before creating a manifest or Helm ChangeSet. Keep execution disabled until testing on a non-production cluster.

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
- `hermes-control-plane-kubernetes-broker`
- `hermes-control-plane-node-agent`

The Kubernetes Broker re-enforces target scope (`namespace_allowlist`/`namespace_denylist`, optional kind allow/deny lists, and cluster-scoped permission) immediately before preview and execution. It selects a compatible bundled kubectl per target and binds the selected client/server versions plus the kubectl binary hash into the preview/execution boundary.

9router, OmniRoute, and Hermes Agent are upstream images and are not rebuilt here.

Manual fallback build/publish remains available:

```bash
IMAGE_NAMESPACE=afsharidevops VERSION=0.5.10 ./scripts/push-images.sh
```

## Verify

```bash
./scripts/verify.sh
```

CI runs the Control Plane stable safety suite, Kubernetes Broker policy/ticket tests, full Smart Router regression suite, Compose/static security validation, and Helm lint.

## Security status

The Control Plane API does not accept raw kubeconfig material. Kubernetes/Helm mutation requires live broker preview plus the exact approved ChangeSet and is disabled by default. Read `SECURITY.md` before enabling execution.

9router and OmniRoute Router Gateway API credentials are provisioned automatically by `./hermesctl up`; no dashboard key copy/paste is required.

For 9router, `hermesctl` also reconciles the routing objects expected by Router Gateway: `ai`, `combo-fast`, `combo-standard`, and `combo-strong`. The `ai` combo is refreshed from the current OpenCode free-model catalog; tier combos are created only when missing and are then operator-owned so dashboard customizations are preserved. OmniRoute keeps its native `auto/best-*` routing and does not require synthetic combos.
