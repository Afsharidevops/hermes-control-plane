# Hermes Control Plane

> **Start with the [Hermes Operator Guide](docs/guide/README.md).** It provides zero-to-one Docker and Helm deployment, the full configuration reference, every UI surface, governance and operations workflows, CLI and API references, and explicit runtime-evidence boundaries.

> v0.5.11 includes Radar runtime, Cilium/Hubble Network Live, executable native diagnostics, a full Hermes-native Operator Center UI scope contract, bounded trusted-Kubernetes day-2 execution, active unified cluster verification, a Batch C trusted Redfish infrastructure execution path (**Integration/local evidence**; disposable real-target evidence remains required), read-only Proxmox capacity and VM-inventory collectors, and a disabled-by-default worker-only QEMU Proxmox mutation runtime. The Proxmox runtime supports only eight governed QEMU actions and has local/mock evidence only; it is not capacity-backed Cluster Factory lifecycle or real-provider proof. UI state is reported separately from provider/runtime completion.

Hermes Control Plane is a self-hosted, AI-assisted DevOps control plane designed to run on a Docker/VM installation or Kubernetes while keeping privileged credentials and infrastructure execution outside the LLM trust boundary.

> **v0.5.11 (released):** built forward-only from frozen `v0.5.11-dev.4`. The runtime includes Radar, Cilium/Hubble, native diagnostics, Operator Center, bounded Kubernetes day-2, unified verification, Argo CD/Cilium/Velero operations, digest-pinned blob/OCI/Helm/Git/Ansible artifact mirroring, ClusterBlueprint dependency resolution and READY offline-manifest binding, plus Batch A signed APT/RPM/Python repository snapshots and development image-publication suppression. Merged Batch B adds a disabled-by-default trusted provider worker on the existing Node Agent image for exact-ticket-bound offline Kubespray v2.28.1, K3s and RKE2 execution, with deterministic offline reference consumption, private staged SSH profiles, fixed playbook/command vectors, bounded worker lifecycle, Kubernetes upgrades, certificate rotation, existing-host maintenance, and K3s/RKE2 embedded-etcd snapshot/restore and existing-host DR with active verification. Batch B deliberately fails closed for capacity-backed Cluster Factory lifecycle and continues requiring existing, pre-registered preflight-PASS servers. Batch C adds a disabled-by-default trusted Redfish worker, constrained IPMI fallback, private-offline PXE/iPXE provisioning, Redfish disk/RAID and platform-state runtime, constrained C9 RESTCONF, read-only Proxmox collectors, and a narrow worker-only QEMU Proxmox mutation runtime for exactly eight governed operations. Those paths use mounted worker credentials, active preview/diff, exact preview-state/artifact drift rejection, signed one-time execution tickets and post-change verification. VMware Workstation/vSphere, OpenStack, AWS, Azure, GCP, and capacity-backed Cluster Factory lifecycle are explicitly deferred to a future release. Normal `dev/**` pushes/PRs validate without publishing all seven images. `v0.5.11` was tagged at commit `237900c2a0d37f0d46383a67d3aea7f99e341a96` after exact-SHA `validate` CI success, and its images are published to Docker Hub as `:0.5.11` and `:latest`.

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
- first-class typed provider foundations for VMware vSphere, VMware Workstation, Proxmox VE, OpenStack, AWS, Azure and GCP (Workstation/Proxmox remain contract-only until their trusted workers land)
- Redfish/IPMI/PXE bare-metal and typed switch/network desired-state contracts
- digest-pinned OCI/Helm/package/Git-release/Ansible and typed APT/RPM/Python repository plans plus executable controlled blob, registry, release-archive, collection-archive and signed/hash-bound repository snapshot synchronization; exact ClusterBlueprint artifact bindings select verified offline destinations and READY manifests are bound into governed provisioning plans/provider-job requests
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

The `v0.5.11` paragraph above is immutable release history. This checkout and its local Helm chart default to `0.5.11`; the expanded operator guide documents that checked-out source surface. Use its [Feature status](docs/guide/feature-status.md) matrix to distinguish stable runtime, integration/local evidence, and deferred capabilities before selecting an image or enabling an optional gate.

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

Pull requests build but do not push. A push to `main` publishes `:edge` and `:sha-...`. A prerelease version tag publishes its matching prerelease image tag. The stable `v0.5.11` tag publishes `:0.5.11` and `:latest`.

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
IMAGE_NAMESPACE=afsharidevops VERSION=0.5.11 ./scripts/push-images.sh
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

- Proxmox capacity collector: disabled by default, reads only from authenticated PVE API `/cluster/resources?type=node`, returns host utilization (CPU cores/memory bytes) with limit/used/headroom per allowlisted node. No VMware Workstation, vSphere, OpenStack, AWS, Azure, or GCP capacity collector exists — those remain contract-only. The collector never returns credentials, executes mutation commands, or fabricates LIVE evidence from deterministic sources. A `LIVE` observation requires every required authenticated upstream request to succeed.

- Proxmox VM inventory collector (`vm.inventory.refresh`): a separate, disabled-by-default read-only collector pinned to `pve-vm-inventory-v1`, independent of the capacity collector's `pve-capacity-v1` pin and the QEMU mutation runtime's `pve-vm-runtime-v1` pin. A `LIVE` observation requires exactly two successful authenticated PVE reads — `/cluster/resources?type=node` then `/cluster/resources?type=vm` — and every allowlisted node must appear in the node response before the VM read is attempted, so an empty VM result is truthful coverage rather than an inferred one. Records are limited to `{vm_id, node, type, power_state, template}`, deterministically sorted, bounded to 512, and filtered to allowlisted nodes; names, IPs, MACs, tags, disk/storage, owner/pool, raw PVE bodies, endpoints and credentials are never returned. This is identity and power-state observation only — not capacity, placement or lifecycle proof. Local/mock test evidence only; no real Proxmox target has returned a `LIVE` VM inventory observation.

- Proxmox QEMU mutation runtime: a separate, disabled-by-default worker-only adapter pinned to `pve-8.2` / `pve-vm-runtime-v1`. It supports exactly `vm.create`, `vm.clone`, `vm.update`, `vm.delete`, `vm.power`, `network.attach`, `snapshot.create`, and `snapshot.restore` through the existing ChangeSet/approval/exact-hash/ticket governance path. The adapter uses fixed HTTPS PVE calls with verified TLS, no redirects or ambient proxies, capability allowlists, active preview/current-hash drift rejection, bounded task polling, and final active readback verification. `vm.delete` and `snapshot.restore` are CRITICAL and require two approvals; the other six are HIGH. It does not implement capacity-backed Cluster Factory lifecycle, automatic rollback, or real-provider proof. See [the operator validation runbook](docs/PROXMOX-VM-RUNTIME-VALIDATION.md).

### 0.5.11-dev.5 day-2 extension
Hermes now also supports ChangeSet-governed exact-commit Argo CD sync, pinned Cilium Helm upgrades, bounded one-shot Velero Backup creation, bounded Velero Schedule create/update, and explicit-namespace Velero Restore through the trusted Kubernetes Broker. Schedule definitions are exact-preview-bound and restricted to fixed 5-field cron expressions that run no more frequently than hourly plus a bounded Backup template; Restore is CRITICAL and requires two distinct approvals. Direct etcd snapshot/restore, full-cluster/provider DR and broader provider/provisioner lifecycle remain in progress.

Batch C infrastructure runtime also includes an optional constrained IPMI LAN+ fallback (`ipmi://host[:port]`) for fixed power/boot operations when Redfish is unavailable. The worker uses `ipmitool` with fixed argv, `shell=False`, and password delivery via worker-only environment; arbitrary IPMI commands are not accepted.

Batch C5b adds a separate PXE/iPXE unattended-provisioning boundary rather than exposing raw iPXE or installer commands. A `pxe` provider must declare `capabilities.network_scope=private-offline` and `capabilities.artifact_delivery=shared-readonly-mirror`; its worker credential profile contains only the private controller bearer token plus worker-side unattended-profile/callback-token file mappings. Planning exact-binds one registered server snapshot (management/provisioning IP plus canonical provisioning NIC/MAC), one existing Redfish/IPMI boot-provider snapshot, and a READY local `file://` PXE artifact manifest for at least kernel/initrd/unattended content. Authorization re-resolves that manifest; execution rehashes files under `HERMES_ARTIFACT_MIRROR_ROOT`, prepares only the fixed HTTPS controller API, sets one-time PXE boot through the already trusted Redfish/IPMI adapter, and requires controller state-history/callback binding plus an active management-port readiness probe before PASS. Raw credentials, callback tokens, generated shell and generated iPXE scripts are excluded from plans/evidence.

Batch C7 adds bounded platform-firmware state on the trusted Redfish worker: `secure-boot.apply`, `sriov.apply`, `iommu.apply`, and persistent `boot-order.apply`. Secure Boot requires reboot activation because Redfish `SecureBootEnable` is a next-boot setting; active verification checks `SecureBootCurrentBoot` after the governed reset. SR-IOV/IOMMU use only provider-declared BIOS attribute/value mappings that are also BIOS-allowlisted, and persistent boot order is limited to provider-allowlisted, actively discovered, enabled `BootOptionReference` values. Reboot-activated mutations require an already-powered-on system, use only a provider-declared fixed Redfish reset type, tolerate only bounded transient BMC unavailability during restart, and PASS only when active post-reboot state matches.
