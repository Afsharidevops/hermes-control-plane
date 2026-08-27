# Hermes Control Plane 0.5.11 release status

Status: **RELEASED — TAGGED `v0.5.11` / PUBLISHED**

Release boundary:

- commit: `237900c2a0d37f0d46383a67d3aea7f99e341a96`
- tag: `v0.5.11`
- branch: `dev/0.5.11`
- exact-SHA `validate` CI: success
- Docker Hub images: published as `:0.5.11` and `:latest` (six images, `Build and Publish Docker Images` workflow success)
- GitHub Release: https://github.com/Afsharidevops/hermes-control-plane/releases/tag/v0.5.11

This release went straight from dev.5 scope closure to the stable `v0.5.11` tag; no separate `v0.5.11-dev.5` tag was created. The scope-closure work recorded below is the content that shipped in `v0.5.11`.

Frozen parent boundary:

- commit: `d4eb9b7ab2564301c09b8c0d36a2e9d53b843273`
- tag: `v0.5.11-dev.4`
- branch: `dev/0.5.11`

Do not amend, reset, squash, force-push, move or recreate the frozen dev.4 tag, or the released `v0.5.11` tag.

## Completed dev.5 runtime slices

- real read-only Radar HTTP MCP client
- MCP initialize/session handling
- fixed read-only tool allowlist
- executable `AUTO`, `RADAR`, `NATIVE` modes
- same-environment Radar/native Kubernetes target isolation
- AUTO fallback through the existing Kubernetes Broker
- strict RADAR fail-closed behavior
- defense-in-depth Secret/env/token redaction
- Hermes-native live intelligence controls
- dev.5 source/security/static gates and release guards anchored to frozen dev.4
- Cilium/Hubble live-network runtime through the trusted Kubernetes Broker, including namespace authorization, redaction/aggregation, bounded history, SSE and Hermes-native Network Live UI
- executable Hermes-native Kubernetes diagnostics for core health, OOM/metrics/storage/events, Cilium/Hubble/DNS/ingress/NetworkPolicy, RBAC/workload security, Argo CD and rollout checks
- diagnostics target-scope enforcement, fixed read-only collectors, bounded typed findings, no Secret/env/log reads, mutation attestation and Control Plane sensitive-evidence rejection
- Hermes-native Operator Center UI contract and navigation covering the complete promised Kubernetes, Cluster Factory, infrastructure, operations and governance surface map while keeping UI state separate from runtime/provider state
- live Operator Center views for current registries, ChangeSets/audit, Radar/Hubble intelligence summaries, native diagnostics, cluster/server/provisioning state and operation/verification data without adding mutation/approval bypass controls
- trusted Kubernetes Broker day-2 runtime for node cordon/uncordon/drain, workload restart/scale and pinned Helm-backed add-on/apply operations
- day-2 runtime planning now binds a broker-produced read-only live preview/precondition into the exact typed plan before approval, rejects live-state drift at execution, and persists active typed verification automatically
- active unified cluster verification engine that executes live Kubernetes Broker probes, persists typed PASS/WARN/FAIL/SKIP results, optionally checks configured Radar health, and explicitly SKIPs unsupported provider/etcd/agent probes rather than inventing evidence
- opt-in `host-network-local-v1` host observer: a separate credential-free, read-only workload with a dedicated token and fixed host-network collector. Unified `hosts` verification accepts only fresh bounded evidence from an explicit persisted server-to-observer identity binding; missing host roots/bindings remain SKIP, mismatched or unsafe configured observer results fail, and one observer cannot be inferred to cover other cluster servers.
- ChangeSet-governed artifact blob synchronization runtime for controlled `file://` or allowlisted `https://` sources into the local mirror root, with byte/time bounds, redirect/root/symlink rejection, atomic writes, idempotent retries and independent source/destination SHA-256 verification
- trusted digest-pinned OCI-image registry-to-registry synchronization with source/destination registry allowlists, full multi-arch copy, preserved digests, idempotent tag verification and no shell/raw-credential exposure
- trusted typed Helm OCI chart registry-to-registry synchronization with SemVer-compatible immutable tags, Helm config/chart-layer media-type validation, digest preservation, destination read-back verification, idempotency and non-Helm artifact rejection
- deterministic ClusterBlueprint artifact dependency resolution with explicit artifact-ID binding, required provider/Kubernetes/add-on version coverage, verified offline destination selection, dependency-key uniqueness, DAG ordering/cycle rejection, and partial-sync resume evidence without credential material
- offline provisioning-plan artifact binding that requires a READY integrity-checked ClusterBlueprint artifact manifest, copies only verified destination/digest metadata into the exact ChangeSet and per-node provider-job request, and rechecks the current manifest hash before provider-job authorization
- bounded exact-tag Git release archive synchronization for allowlisted public HTTPS repositories, with immutable tag+commit binding, fixed credential-free Git transport, submodule rejection, canonical archive SHA-256 verification, atomic publication and idempotent retry; exact-SHA `validate` is green at `395059d63d86316d3056cd28790941726c7e42dd` (run `32477791912`)
- typed digest-pinned Ansible Galaxy collection archive synchronization with exact namespace/name/SemVer identity, MANIFEST.json -> FILES.json checksum binding, per-file SHA-256 verification, unsafe tar member rejection and no filesystem extraction; exact-SHA CI green at `26855cbb6f45176ee99029cdbc29b7c847ae79b6` (run `32478857268`)
- merged Batch A delivery substrate is committed/pushed and exact-SHA `validate` CI-green at `aab6d31ac8af598ee7d9651543137776ca82391b` (run `32481855314`): signed APT repository snapshots (Release.gpg -> Release SHA256 -> Packages -> .deb), signed RPM repository snapshots (repomd.xml.asc -> repomd SHA256 -> primary -> .rpm), and PEP 503-style Python Simple snapshots with `#sha256=` distribution binding; atomic staging/rollback, idempotency, bounded HTTPS retries and environment-mounted auth/keyrings are enforced
- development Docker image publication is decoupled from `dev/**` pushes: `validate` remains branch-triggered while `publish-images` stays on main/tags/manual publication boundaries
- trusted Argo CD GitOps sync runtime bound to a full approved commit digest, with Application state-drift rejection, fixed server-side patching, sync wait and active sync/health verification
- trusted pinned Cilium Helm upgrade runtime with exact release-state preconditions plus active Helm, Cilium-agent and sanitized Hubble verification
- trusted one-shot Velero Backup runtime with exact backup-state preconditions, fixed CR creation, namespace-scope enforcement and active completion/error/snapshot-count verification
- trusted bounded Velero Restore runtime for explicit namespaces with CRITICAL two-person approval, exact source-Backup/Restore-state preconditions, fixed non-destructive CR creation and active completion/error/plugin-operation verification
- trusted Velero Schedule create/update runtime with fixed no-more-frequent-than-hourly cron, exact live-state binding, namespace scope enforcement, bounded Backup template fields and active validation/spec verification

- merged Batch B trusted existing-host cluster provider runtime: disabled by default on the existing Node Agent image; exact HMAC-signed ChangeSet/typed-plan tickets; one-time ticket replay rejection; private per-execution SSH credential staging; fixed no-shell/no-caller-CLI provider execution; Kubespray v2.28.1 plus pinned Ansible dependency contract; role-aware offline K3s/RKE2 server/agent installation; deterministic offline registry/file/package/PyPI binding; worker add/remove/replace; Kubernetes upgrades; certificate rotation; bounded existing-host maintenance; direct K3s/RKE2 embedded-etcd snapshot/restore and existing-host DR; active service/API/snapshot/reset-state verification; execution output and raw credentials suppressed
- Batch C Redfish infrastructure runtime foundation is implemented locally: `inventory.refresh`, `power.set`, `boot.set`, `virtual-media.insert`, `virtual-media.eject`, bounded `bios.apply` and allowlisted `firmware.apply` use the existing Node Agent as a disabled-by-default `infrastructure-provider-worker`; credentials are resolved only from worker-mounted profiles, planning binds an active credential-free current-state preview/diff, execution rejects state drift, one-time HMAC-signed tickets bind the exact typed-plan hash, mutations use fixed Redfish API actions only, redirects/non-HTTPS are rejected by default, and post-change state is actively verified. This is local/integration evidence only until committed/pushed/exact-SHA CI-green and, separately, exercised against a disposable real target.
- Batch C5a constrained IPMI LAN+ fallback is implemented locally for fixed `power.set`/`boot.set` with worker-only password delivery, fixed no-shell `ipmitool` argv, exact preview drift binding and active state verification.
- Batch C5b PXE/iPXE unattended provisioning is implemented locally through a private-offline HTTPS controller: exact Server/NIC/MAC and trusted Redfish/IPMI boot-provider snapshots, READY local artifact-manifest binding/recheck/worker rehash, worker-only unattended/callback secret references, fixed one-time PXE boot, exact callback/plan/artifact binding, monotonic provisioning-state history and active post-install host readiness. No generated shell/iPXE command surface or public artifact fetch is accepted.
- Batch C6 Redfish disk/RAID desired-state runtime is implemented locally with exact controller/drive/RAID/name allowlists, stable physical-drive identity binding, idempotent volume create and separately governed CRITICAL volume delete with active verification.
- Batch C7 Redfish platform-state runtime is implemented locally for Secure Boot, provider-mapped SR-IOV/IOMMU and persistent BootOrder, with fixed activation/reset policy and active post-reboot verification. Proxmox read-only capacity and VM-inventory collectors remain separate disabled-by-default provider registrations; VMware Workstation remains contract-only for capacity.
- Proxmox QEMU VM mutation runtime is implemented locally as a separate disabled-by-default worker-only adapter pinned to `pve-8.2` / `pve-vm-runtime-v1`. It supports exactly `vm.create`, `vm.clone`, `vm.update`, `vm.delete`, `vm.power`, `network.attach`, `snapshot.create`, and `snapshot.restore`; uses strict typed desired states and capability allowlists; binds active preview/current hashes into a one-time signed ticket; rejects drift and replay; uses fixed HTTPS PVE API calls with verified TLS, no ambient proxies or redirects, bounded task polling, and active readback verification. `vm.delete` and `snapshot.restore` are CRITICAL and require two approvals; the other six operations are HIGH. It is local/mock test evidence only, has no automatic rollback, and must not be represented as real-provider validated until an operator supplies sanitized disposable-target evidence at the exact pushed SHA.
- Batch C9 network-switch runtime is implemented locally for exactly one pinned `openconfig-restconf-v1` profile: allowlisted `vlan.ensure`, `port.configure`, and read-only `lldp.observe`. It requires HTTPS IP-literal endpoints at the fixed `/restconf/data` root, uses no ambient proxy or redirects, applies fixed OpenConfig RESTCONF payloads conditionally with ETags, rejects preview drift, and records bounded active verification. It remains disabled by default and is local/mock integration evidence only.
- C10/C11 read-only Proxmox capacity collector: disabled by default on the Node Agent; reads authenticated PVE API `/cluster/resources?type=node`; returns sanitized host utilization (CPU cores/memory bytes) with limit/used/headroom per allowlisted node; attests credential_material_returned, mutation_commands_executed, arbitrary_cli, and arbitrary_shell are all False; observation_hash is computed from the canonical envelope. VMware Workstation remains contract-only for capacity — its API does not provide verifiable free host capacity. The separate Proxmox QEMU mutation runtime does not provide capacity-backed Cluster Factory lifecycle behavior.
- C10/C11 read-only Proxmox VM inventory collector (`vm.inventory.refresh`): a separate, disabled-by-default Node Agent collector pinned to `pve-vm-inventory-v1`, independent of the capacity collector's `pve-capacity-v1` pin and the QEMU mutation runtime's `pve-vm-runtime-v1` pin. A `LIVE` observation requires exactly two successful authenticated PVE reads — `/cluster/resources?type=node` then `/cluster/resources?type=vm` — and every configured allowlisted node must appear in the node response before the VM read is attempted, so an empty VM result is truthful coverage rather than an inferred one. Records are restricted to `{vm_id, node, type, power_state, template}`, deterministically sorted by `(node, vm_id)`, bounded to 512 entries, and filtered to allowlisted nodes; names, IPs, MACs, tags, disk/storage, owner/pool, raw PVE bodies, credentials and endpoints are never returned. The Control Plane independently re-validates the worker result (exact key sets, forbidden sensitive keys, staleness, safety flags, source metadata, record identity/state/sort/uniqueness and observation hash) before auditing `provider.vm_inventory.refreshed`. This is not capacity, placement or lifecycle proof. Local/mock test evidence only; no disposable real Proxmox target has returned a `LIVE` VM inventory observation.

## Deferred or separately evidenced work

- Capacity-backed Cluster Factory lifecycle (C11): VM allocation to registered servers, infrastructure creation/destruction/scale, true cluster decommission, capacity-backed template cloning, and provider recreation/DR are explicitly deferred. Cluster Factory remains existing-host/pre-registered-server only.
- Kubespray direct-etcd snapshot/restore/DR remains fail-closed; Batch B direct embedded-etcd recovery is bounded to K3s/RKE2
- remaining provider/bare-metal/network executors for the intended original scope: Redfish inventory/power/boot/virtual-media/BIOS/firmware, constrained IPMI fallback and private-offline PXE/iPXE unattended provisioning now have local integration runtime; Redfish disk/RAID plus Secure Boot/SR-IOV/IOMMU/persistent boot-order state now have local integration runtime; the narrow C9 switch VLAN/port/LLDP RESTCONF profile now has local integration runtime. Management/provisioning-network execution, NETCONF, generic RESTCONF, hostname endpoints, BGP, bonds, attach/detach, and other switch vendors remain open. VMware vSphere/VMware Workstation, OpenStack, AWS, Azure, and GCP mutation/capacity runtime are explicitly deferred to a later release; VMware Workstation capacity remains contract-only.
- matching host/direct-etcd/provider/bare-metal/network/cloud active verification collectors; unsupported collectors remain SKIP
- broader non-Argo GitOps or full Git-history/submodule/Galaxy-role API behavior only if the final original-scope audit proves those capabilities were promised
- disposable real-target repeatability/evidence where available; never convert local integration into invented real-target evidence
- final full scope-conformance re-audit and dev.5 release gate

`v0.5.11` was created only after the full dev.5 closure scope above was complete,
local validation (`./validate.sh`) passed, and branch CI succeeded on the exact
tagged SHA `237900c2a0d37f0d46383a67d3aea7f99e341a96`.

- Batch C5a/C5b adds constrained IPMI LAN+ power/boot fallback plus private-offline PXE/iPXE unattended provisioning with exact artifact/callback/state-machine binding and active host-readiness verification.
- Batch C6 adds allowlisted Redfish disk/RAID volume create/delete with exact physical-drive identity/topology preview binding, CRITICAL destructive-delete governance and active post-change verification.
