- Dev.5 read-only Proxmox VM inventory slice: add the distinct disabled-by-default `vm.inventory.refresh` Node Agent collector, pinned to `pve-vm-inventory-v1` separately from capacity. A `LIVE` observation requires exactly two authenticated PVE reads (`/cluster/resources?type=node`, then `?type=vm`) and verified allowlisted-node coverage before the VM request. Return only bounded/sorted `{vm_id, node, type, power_state, template}` records with a canonical observation hash; independently reject stale, unsafe, secret-shaped, malformed, non-unique or tampered worker output before audit. The collector is identity/power-state observation only — not capacity, placement or lifecycle proof — and all Proxmox VM mutations remain `CONTRACT_ONLY`. Local/mock evidence only; no real Proxmox target has produced `LIVE` inventory evidence.
- Dev.5 Batch C6 local continuation: add constrained Redfish disk/RAID desired-state runtime for allowlisted storage controllers, physical drives, RAID types and volume names; preview binds exact drive identity/serial/model/capacity and existing volume topology, rejects in-use/ambiguous drives and destructive in-place RAID reshapes, creates volumes only through fixed Redfish VolumeCollection POST, requires an explicit separately approved CRITICAL `storage.volume.delete` ChangeSet for deletion, and actively verifies the resulting volume topology. Secure Boot/SR-IOV/IOMMU/boot-order, management/provisioning network, switch/network, cloud/virtualization capacity and provider-backed lifecycle/DR remain open.
- Dev.5 Batch C5b local continuation: add trusted PXE/iPXE unattended OS provisioning through a private-offline HTTPS controller with exact Server/NIC/MAC + Redfish/IPMI boot-provider snapshots, READY local artifact-manifest binding and worker-side rehash, structured unattended profiles, callback-token hash/plan binding, monotonic requested→booting→installer-started→installing→complete proof, one-time network boot, host-readiness verification, replay/drift rejection and no generated shell/iPXE script surface; disk/RAID, Secure Boot/SR-IOV/IOMMU and network/provider-capacity runtime remain open.
- Dev.5 Batch C local firmware continuation: add allowlisted exact-component Redfish `firmware.apply` through `UpdateService.SimpleUpdate`, with credential-free HTTPS image selection, exact current-version preview binding, state-drift rejection, idempotent already-converged handling and bounded active version verification; IPMI/PXE, disk/RAID, network and provider-capacity runtime remain open.
- Dev.5 Batch C local continuation: add the first trusted infrastructure-provider runtime on the existing Node Agent for Redfish `inventory.refresh`, `power.set`, `boot.set`, `virtual-media.insert`, `virtual-media.eject` and bounded `bios.apply`; bind an active credential-free current-state preview into the exact typed plan, reject preview-state drift before mutation, require one-time HMAC-signed `infrastructure-provider-worker` tickets, use only fixed Redfish API mutations, and actively verify post-change state. Execution remains disabled by default; IPMI/PXE, firmware/RAID, switch/network, VMware/OpenStack/AWS/Azure/GCP capacity execution and their real-target collectors remain open.
- Dev.5 merged Batch B: add a disabled-by-default trusted cluster provider worker on the existing Node Agent image for exact-ticket-bound offline Kubespray v2.28.1, K3s and RKE2 provisioning/day-2 execution; bind READY artifact manifests into deterministic offline runtime inputs, stage SSH credentials only inside private per-execution workspaces, actively verify retained nodes/API/snapshots, and add bounded worker lifecycle, Kubernetes upgrade, certificate rotation, maintenance, K3s/RKE2 embedded-etcd snapshot/restore and existing-host DR paths. Provider-capacity creation/destruction, true decommission/scale/template cloning, Kubespray direct-etcd recovery and real-target/provider collectors remain open for Batch C.
- Dev.5 Ansible collection mirror continuation: add typed digest-pinned Galaxy collection tarball mirroring with exact namespace/name/SemVer binding, root MANIFEST.json/FILES.json verification, internal SHA-256 file-manifest checks, unsafe tar member rejection, atomic/idempotent publication and no extraction; Galaxy catalog/server, standalone roles and signature policy remain open.
- Dev.5 Git release mirror continuation: add bounded allowlisted-HTTPS exact-tag/exact-commit Git release archive synchronization with fixed credential-free Git commands, redirect/non-HTTPS rejection, submodule rejection, canonical tar SHA-256 verification, atomic/idempotent destination handling and no caller Git flags; full Git repository/submodule/signature closure and provisioner execution remain open.
- Dev.5 offline provisioning-plan artifact binding slice: provisioning runs with ClusterBlueprint artifact dependencies now require a READY exact-hashed artifact manifest, copy only verified credential-free offline destinations/digests into the typed plan and per-node provider-job request, and reject manifest drift before provider-job authorization; provider-worker consumption/rewrite and repository protocol synchronization remain open.
- Dev.5 ClusterBlueprint artifact dependency resolver slice: blueprints can bind exact mirror artifact IDs and resolve a deterministic verified offline manifest with component/version coverage, credential-free destination selection, explicit DAG ordering/cycle rejection and partial-sync resume evidence; provisioner reference rewriting and package-repository protocol synchronization remain open.
- Dev.5 Helm OCI mirror runtime slice: `helm-chart` artifacts now use the same fixed no-shell Skopeo transport only after Helm-specific OCI manifest validation, SemVer-compatible immutable tag validation, digest-pinned source addressing, independent destination tag/digest verification, idempotent retry, and rejection of non-Helm OCI media types; broader package repository/provenance/dependency-resolution work remains open.
# Changelog

- Dev.5 OCI mirror runtime slice: ChangeSet-governed allowlisted registry-to-registry OCI image copy via fixed Skopeo arguments, full multi-arch copy, preserved digests, environment-only authfile boundary, idempotent destination-tag checks and independent source/destination manifest verification; Helm/package repository protocols remain open.
- Dev.5 artifact mirror runtime slice: ChangeSet-governed controlled file/allowlisted-HTTPS artifact blob synchronization, atomic publication, idempotent retry and independent source/destination SHA-256 verification; unsupported OCI/repository protocol pairs remain explicit contracts.
- Dev.5 active unified verification slice: live Kubernetes-broker probes mapped into deterministic PASS/WARN/FAIL/SKIP checks, optional active Radar health, bounded/redacted evidence, persistence and audit; unsupported host/etcd/agent/provider probes remain explicit SKIP instead of synthetic success.
- Dev.5 trusted Kubernetes day-2 runtime slice: exact-preview-bound node cordon/uncordon/drain, workload restart/scale and pinned Helm-backed add-on/apply execution through the Kubernetes Broker with drift rejection and persisted active verification.
- Dev.5 Operator Center UI slice: typed full-scope operator navigation for Kubernetes, Cluster Factory, infrastructure, operations and governance, with live data where available and explicit PARTIAL/CONTRACT_ONLY runtime states where executors are not yet complete.
- Dev.5 native diagnostics runtime slice: executable broker-owned read-only checks for node/pod/workload/OOM/metrics/storage/events, Cilium/Hubble/DNS/ingress/NetworkPolicy, RBAC/workload security, Argo CD and rollout health with target-scope enforcement and bounded typed evidence.
- Dev.5 Hubble runtime slice: trusted Kubernetes Broker collector, pinned Hubble CLI, namespace authorization, typed redaction/aggregation, bounded history, SSE, and Hermes-native Network Live batch UI.

## 0.5.11

- add a disabled-by-default, worker-only Proxmox QEMU VM mutation runtime pinned to `pve-8.2` / `pve-vm-runtime-v1`, supporting exactly `vm.create`, `vm.clone`, `vm.update`, `vm.delete`, `vm.power`, `network.attach`, `snapshot.create`, and `snapshot.restore` through the existing ChangeSet/approval/exact-hash/ticket pipeline; `vm.delete` and `snapshot.restore` are CRITICAL (two approvals), the other six are HIGH (one approval)
- add read-only Proxmox capacity (`pve-capacity-v1`) and VM-inventory (`pve-vm-inventory-v1`) collectors as separate disabled-by-default provider registrations, independent of the mutation-runtime pin
- add the operator-only Proxmox VM runtime validation runbook (`docs/PROXMOX-VM-RUNTIME-VALIDATION.md`)
- update dev.5 source-security and config-static gates to assert the exact eight-operation Proxmox allowlist, required config parity, and runbook presence
- explicitly defer VMware Workstation/vSphere, OpenStack, AWS, Azure, and GCP mutation/capacity runtime, and capacity-backed Cluster Factory lifecycle (C11), to a future release
- tag `v0.5.11` at commit `237900c2a0d37f0d46383a67d3aea7f99e341a96` after exact-SHA `validate` CI success; publish all six Docker Hub images as `:0.5.11` and `:latest`

## 0.5.11-dev.5 (scope-closure work, shipped in v0.5.11)

- begin scope-closure work on top of frozen `v0.5.11-dev.4` without rewriting frozen history
- add a real HTTP MCP Radar read adapter with initialization/session handling and a fixed allowlist for dashboard, issues, resource list/detail, search, topology and neighborhood
- make Radar a first-class integration kind and add executable `AUTO`, `RADAR`, and `NATIVE` cluster-intelligence query modes
- add same-environment Radar/native-target isolation, strict RADAR fail-closed behavior and AUTO fallback through the existing constrained Kubernetes Broker
- add defense-in-depth redaction for Kubernetes Secret bodies, direct workload environment values, authorization/token/password-shaped fields, and bounded provider responses
- explicitly forbid direct Control Plane credential-material resolution for authenticated Radar endpoints; authenticated provider access must use a credential-service/provider-worker boundary
- add Hermes-native live intelligence controls and dev.5 Radar runtime/security regression tests
- move guarded apply/validate/push scripts and CI source gates to the exact frozen dev.4 boundary and dev.5 version
- add trusted artifact blob synchronization runtime with no redirects or embedded credentials, source/destination root confinement, byte/time limits, exact digest verification, idempotent retry, persisted verification and audit; full registry/repository protocol synchronization remains open

## 0.5.11-dev.4

- add a shared typed Operations Center intent backend for Web/UI, Telegram, Hermes Bot/AI and API channels while keeping mutations bot-authenticated and ChangeSet-governed
- add centralized fleet views/selectors with exact cluster target snapshots and fail-closed target-drift authorization
- add advanced deterministic day-2 plan contracts for worker/node/workload/add-on/Helm/GitOps/upgrades/etcd/restore/certificates/maintenance/decommission/scaling/cloning/DR
- add first-class typed provider foundations for VMware, OpenStack, AWS, Azure and GCP with explicit API/provider-worker version pins and Credential Service references only
- add typed Redfish, IPMI and PXE bare-metal contracts plus switch/network desired-state contracts without arbitrary generated shell/CLI
- add digest-pinned OCI image, Helm chart, package and Git/release artifact mirroring plans with source/destination SHA-256 verification stages
- add generic constrained operation jobs with integrity-checked approvals, exact typed-plan/hash binding, short-lived HMAC-signed execution tickets, one-time approval consumption at execution start, and provider/cluster/artifact/fleet target-drift rejection
- add persisted unified typed verification results with secret-shaped evidence rejection
- add Hermes-native Operations Center fleet/provider/artifact/job/verification observability pages without mutation/approval bypass controls
- add dev.4 source-security/config-static gates and guarded apply/validate/push scripts bound to frozen dev.3; dev.4 tagging additionally requires the exact branch-CI-green SHA

## 0.5.11-dev.3

- add persisted typed ClusterBlueprint, ClusterProfile, Cluster, NodeRole, ProvisioningRun, AddonPlan, UpgradePlan and BackupPlan resources
- add deterministic production Kubespray, lab/edge K3s and hardened RKE2 execution-spec contracts sourced from Server Registry and PASS preflight state, with explicit provider-version pins
- bind cluster provisioning to HIGH-risk ChangeSets and exact-hash provider jobs per node
- make Cilium the Cluster Factory network contract and retain Hubble authorization/redaction/aggregation requirements
- add Hermes-native Cluster Factory and Radar/Hubble intelligence UI views without adding mutation bypasses
- add five deterministic operational profiles (`lab-minimal`, `lab-full`, `production`, `production-ha`, `production-hardened`) plus governed Cilium/Hubble, kube-vip, MetalLB, storage, ingress, TLS, GitOps, observability, cost and backup add-ons with explicit version-pin requirements
- add typed upgrade and backup planning foundations plus native read-only diagnostics inspired by useful Aban ideas without a kubectl-aban-plugin runtime dependency
- add dev.3 source/security and config/static gates and update apply/validate/push handoff scripts for the frozen dev.2 boundary

## 0.5.11-dev.2

- complete the isolated Credential Service with encrypted local storage, external references, safe metadata/name update, rotation, revocation, safe testing, metadata-only synchronization, audit and failure-closed behavior
- add Server Registry with environment/site/rack/zone labels, pinned SSH host fingerprints, duplicate-IP controls, SSH/BMC credential bindings and discovered inventory
- add deterministic fixed read-only SSH/host preflight ChangeSets and provider-job result binding
- add generic provider lifecycle descriptors for SSH, Kubespray, K3s, RKE2, Radar and Hubble
- add HIGH-risk bootstrap ChangeSet planning gated by PASS preflight, policy, approval and exact plan hash
- add provider-job stage events, SSE log/status streaming, pause/resume and bounded retry foundation
- make Radar/Hubble first-class while explicitly prohibiting governance bypass and requiring Hubble authorization/redaction/aggregation before AI/UI
- add the Credential Service to the GitHub Actions multi-arch Docker image matrix and use Docker Hub username/token from GitHub Secrets
- add dev.2 source/security and static configuration gates plus separate apply/validate/push handoff scripts
- keep local push logic source/tag-only; production image publishing remains GitHub Actions -> Docker Hub

## 0.5.11-dev.1

- add the compressed v0.5.11 completion roadmap
- add audited Application registry CRUD
- add shared adapter capability/security contract discovery
- add policy-bound signed agent task envelopes with capability enforcement
- add one-time agent task claim/replay protection and audited results
- add Docker/Helm/hermesctl wiring for a separate agent-task HMAC key
- add a dedicated 0.5.11-dev.1 source/security gate

## 0.5.10 (stable candidate)

- Server-authoritative policy generation with stale-plan invalidation.
- Two-person CRITICAL exact-hash approval; approval nonce/HMAC integrity and one-use consumption.
- Credential-reference secret rejection and audited rotation, including SSH/Kubernetes lifecycle coverage.
- Agent one-time enrollment, replay protection, capability heartbeat and revocation.
- Audit export/digest and retention controls.
- Integrity-checked backup/restore and single-active failover acceptance.
- Stable candidate image/runtime/migration gates and CI runtime-action maintenance.


## 0.5.10-rc.1 (development)

- fix Kubernetes discovery JSON handling so large structured results are parsed from stdout without silent 100 KB truncation
- add target-aware bundled kubectl 1.33-1.36 selection with exact-minor preference and supported one-minor fallback
- bind Kubernetes server version, selected kubectl version, binary SHA-256, and toolchain binding hash into live preview and signed execution tickets
- reject execution when the target/toolchain binding changes after preview, requiring a fresh preview and approval
- validate 35 non-destructive security/authorization checks and 32 controlled execution/drift/replay/rollback checks on the disposable sandbox target
- isolate Control Plane and Kubernetes Broker CI test environments because their dev requirement sets intentionally pin different pytest versions
- fix RC.1 stabilization R1 combo bootstrap abort: tolerate EOF from tiny action files under `set -e` and newline-terminate reconciliation plan files
- keep the R1 9router combo reconciliation design while ensuring first-run combo creation actually executes
- preserve Hermes Smart Router authentication with `api_key: ${OPENAI_API_KEY}` rather than clearing the config reference
- make `bot check` verify an authenticated Hermes -> Smart Router runtime request
- automatically reconcile 9router `ai`, `combo-fast`, `combo-standard`, and `combo-strong` routing objects from the current OpenCode free-model catalog
- preserve operator-customized tier combos after initial creation while refreshing the Hermes-managed `ai` combo when the catalog is available
- keep existing 9router combos usable during a temporary OpenCode catalog outage
- leave OmniRoute on its native `auto/best-*` routing path with no synthetic combo provisioning
- upgrade `router probe` from a model-list check to a real streaming chat-completion request
- preserve the original `managed_key_stale_ids` exit status so ambiguous active-key cleanup reports the dedicated fail-closed error
- document `router cleanup-keys` in CLI help

## 0.5.10-beta.1

- add isolated Kubernetes Broker image with kubectl/Helm
- add kubeconfig local-reference/fingerprint boundary for Docker/VM
- add ChangeSet schema v2 target snapshots and drift invalidation
- add Kubernetes discovery, server-side manifest dry-run/diff and guarded apply
- add Helm server dry-run, install/upgrade verification and rollback flow
- add signed short-lived exact-plan execution tickets
- keep Kubernetes and Control Plane execution disabled by default
- add Kubernetes-focused Operations Center workflows
- add hermesctl kubeconfig/version/upgrade commands
- add Docker Compose/Helm/CI wiring for Kubernetes Broker

## 0.5.10-alpha.2

- merged Integration Registry and ChangeSet milestones into one Management + Safety Core release
- added persistent Environment, Integration, Target and credential-reference registries
- added alpha.1 SQLite schema migration/backfill
- added starter Operations Center management UI at `/ui`
- added HTTP/HTTPS integration health-test foundation
- added deterministic canonical ChangeSet plan serialization and SHA-256 hashes
- added automatic READ/LOW/HIGH/CRITICAL risk classification
- added ChangeSet preview, expiry and state management
- added approval request/approve/reject/cancel flows bound to the exact plan hash
- blocked HIGH/CRITICAL requester self-approval
- added append-oriented audit events
- added Control Plane API tests to CI
- changed Docker publishing to GitHub Actions: `edge`/`sha-*` on main, semver tags on releases, `latest` only for stable versions
- kept privileged DevOps execution disabled pending beta adapters

## 0.5.10-alpha.1

- created Hermes Control Plane monorepo foundation
- migrated Smart Router and Execution Broker foundations
- added runtime-selectable 9router/OmniRoute gateway
- added Docker Compose and initial Helm deployment
- introduced isolated `hermes-control-plane-*` Docker image naming

- 0.5.11-dev.5: add exact-commit Argo CD GitOps sync and pinned Cilium upgrade execution through the trusted Kubernetes Broker with drift-bound previews and active verification.
- 0.5.11-dev.5: add bounded one-shot Velero Backup execution through the trusted Kubernetes Broker with exact state/spec binding and active completion verification.

- dev.5 scope closure: add CRITICAL two-approval explicit-namespace Velero Restore runtime with exact source/restore drift binding, fixed non-destructive Restore CR execution, PV permission gating and active terminal verification.

- dev.5 scope closure: add exact-preview-bound Velero Schedule create/update runtime with bounded hourly-or-slower cron, fixed Backup template fields, namespace authorization, unsupported-field rejection and active validation/spec verification.

- 0.5.11-dev.5 Batch A: stop Docker image publication on normal `dev/**` pushes while retaining exact-SHA `validate`; add typed signed APT/RPM and hash-bound Python repository snapshot runtimes with atomic directory publication, trusted environment-mounted HTTPS auth/keyring delivery, bounded retry/timeout/idempotency and partial-sync rollback.

- Dev.5 merged Batch C continuation: add constrained IPMI LAN+ fallback runtime for fixed power/boot operations using one-time signed infrastructure tickets, worker-only password delivery via `IPMI_PASSWORD`, deterministic state preview/drift rejection and active verification; no shell or caller-supplied IPMI command surface.

- Dev.5 merged Batch C7: add bounded Redfish Secure Boot, provider-mapped SR-IOV/IOMMU and persistent BootOrder runtime with exact allowlists, active-state preview binding, reboot activation governance and post-reboot verification; add explicit contract-only VMware Workstation and Proxmox VE provider plan targets without claiming their capacity runtime complete.

- Dev.5 scope closure: add a disabled-by-default, worker-only QEMU Proxmox mutation runtime pinned to `pve-8.2` / `pve-vm-runtime-v1` for exactly `vm.create`, `vm.clone`, `vm.update`, `vm.delete`, `vm.power`, `network.attach`, `snapshot.create`, and `snapshot.restore`; require typed capability allowlists, active preview/current-hash drift rejection, one-time signed ticket binding, fixed HTTPS PVE calls, bounded task polling and active readback verification. Classify delete and snapshot restore as CRITICAL/two-approval; retain HIGH governance for the remaining six. VMware Workstation/vSphere, OpenStack, AWS, Azure, GCP, and capacity-backed Cluster Factory lifecycle remain deferred.
