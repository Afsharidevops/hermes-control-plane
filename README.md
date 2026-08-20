# Hermes Control Plane

> Dev.5 scope closure now includes Radar runtime, Cilium/Hubble Network Live, executable native diagnostics, a full Hermes-native Operator Center UI scope contract, bounded trusted-Kubernetes day-2 execution, and active unified cluster verification. UI state is reported separately from provider/runtime completion.

Hermes Control Plane is a self-hosted, AI-assisted DevOps control plane designed to run on a Docker/VM installation or Kubernetes while keeping privileged credentials and infrastructure execution outside the LLM trust boundary.

> **0.5.11-dev.5 scope closure in progress:** dev.5 is forward-only from frozen `v0.5.11-dev.4` and closes runtime gaps found by the full roadmap audit. Radar, Cilium/Hubble, Hermes-native diagnostics, Operator Center, bounded Kubernetes day-2 execution and active unified verification are complete for their current local/runtime-path slices; this source also adds a ChangeSet-governed digest-verified local/allowlisted-HTTPS artifact blob mirror runtime. Dev.5 is not yet release-complete; remaining Cluster Factory/provider executors or explicit deferrals, full OCI/repository air-gap protocols, provider-coupled verification extensions and final scope re-audit remain closure work.

> **0.5.11-dev.4 Full Operations Center + next-deploy infrastructure:** the frozen dev.3 Cluster Factory now feeds a shared Web/Telegram/AI intent backend, exact-snapshot fleet planning, advanced typed day-2 operations, VMware/OpenStack/AWS/Azure/GCP provider foundations, Redfish/IPMI/PXE bare-metal plans, typed switch/network contracts, digest-pinned air-gap mirroring and unified verification. Every mutation remains ChangeSet/policy/approval/exact-hash/target-drift governed, and raw infrastructure credentials remain behind the Credential Service. Production images remain GitHub Actions -> Docker Hub.

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


Dev.4 Operations Center / next-deploy foundation adds:

- shared typed intent planning for Web/UI, Telegram, Hermes Bot/AI and API channels
- centralized fleet registry with environment/labels/sites/zones/health metadata and exact target snapshots
- governed advanced day-2 plans for node, worker, workload, add-on, Helm/GitOps, upgrade, backup/restore, maintenance, decommission, clone and DR operations
- first-class typed provider foundations for VMware, OpenStack, AWS, Azure and GCP
- Redfish/IPMI/PXE bare-metal and typed switch/network desired-state contracts
- digest-pinned OCI/Helm/package/Git-release artifact mirroring plans plus executable controlled file/HTTPS-to-file blob synchronization with source/destination SHA-256 verification
- generic constrained operation jobs with integrity-checked approvals, exact typed-plan/hash binding, signed execution tickets, one-time approval consumption at start, and target-drift authorization
- typed post-operation verification with secret-shaped evidence rejection
- Hermes-native Operations Center observability pages with no mutation/approval bypass controls

See `docs/DEV4-OPERATIONS-CENTER.md`, `PLAN-0.5.11.md`, `SECURITY.md`, and `HANDOVER.md`.

Dev.2 trust/bootstrap foundation adds:

- isolated encrypted Credential Service with metadata-only Control Plane synchronization
- Server Registry with SSH/BMC bindings and pinned host fingerprints
- deterministic read-only SSH/host preflight plans and inventory facts
- provider lifecycle/job foundation with streamed events and bounded retry/resume
- Kubespray/K3s/RKE2 bootstrap planning behind HIGH-risk ChangeSets
- Radar/Hubble first-class provider contracts with Hermes governance preserved

See `docs/DEV2-TRUST-BOOTSTRAP.md`, `PLAN-0.5.11.md`, `SECURITY.md`, and `HANDOVER.md`.

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

- Dev.5 native diagnostics runtime: fixed read-only Kubernetes Broker collectors, target-scope enforcement, bounded typed findings, native security/network/GitOps/rollout checks, and Hermes-side sensitive-evidence rejection.
- Dev.5 Hubble runtime slice: trusted Kubernetes Broker collector, pinned Hubble CLI, namespace authorization, typed redaction/aggregation, bounded history, SSE, and Hermes-native Network Live batch UI.

- trusted Kubernetes day-2 runtime for cordon/uncordon/drain, workload restart/scale and pinned Helm-backed operations with exact live-preview preconditions and active verification

### 0.5.11-dev.5 day-2 extension
Hermes now also supports ChangeSet-governed exact-commit Argo CD sync and pinned Cilium Helm upgrades through the trusted Kubernetes Broker, with precondition-drift rejection and active verification. Broader provider/provisioner lifecycle remains in progress.
