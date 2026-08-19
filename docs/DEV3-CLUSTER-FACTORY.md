# 0.5.11-dev.3 — Cluster Factory + Core Infrastructure / Day-2

## Boundary

This milestone is built on the frozen `0.5.11-dev.2` trust/bootstrap boundary at
`a71b03a54ed2f619d3605c0c08d46de35ad5911c`. It does not replace the Credential
Service, Server Registry, SSH preflight, provider-job lifecycle, or ChangeSet
approval/exact-hash controls.

## First-class lifecycle resources

The Control Plane persists typed contracts for:

- `ClusterBlueprint`
- `ClusterProfile`
- `Cluster`
- `NodeRole`
- `ProvisioningRun`
- `AddonPlan`
- `UpgradePlan`
- `BackupPlan`

Cluster target snapshots include the blueprint provider/version pins, Kubernetes
version, network settings, add-on pins, NodeRole assignments, and the frozen server
snapshots that participate in the existing deterministic ChangeSet hash boundary.

## Operational profiles

Hermes exposes deterministic starting profiles instead of hidden install presets:

- `lab-minimal` — K3s single-control-plane lab/edge baseline;
- `lab-full` — K3s HA lab baseline with storage, ingress, GitOps and observability;
- `production` — Kubespray HA control plane/etcd with kube-vip, MetalLB and core day-2 add-ons;
- `production-ha` — production profile plus topology-spread/PDB/anti-affinity/strong-backup intent;
- `production-hardened` — RKE2 HA hardened/CIS-style baseline.

`POST /v1/cluster-blueprints/from-operational-profile` materializes a preset as a
normal persisted `ClusterBlueprint`; it does not create an execution shortcut.
Provider version and every selected add-on version must be supplied explicitly.

## Cluster creation providers

Cluster provisioning renders deterministic provider payloads rather than generated
shell:

- Kubespray -> `KubesprayExecutionSpec` for the production/default path, with a
  pinned Kubespray provider version, containerd, Server Registry-derived inventory,
  HA control-plane/etcd roles, Cilium, optional kube-vip/MetalLB profile overrides,
  node add/remove lifecycle intent, upgrade workflow, and recoverable stage boundaries.
- K3s -> `K3sExecutionSpec` for lab/edge/lightweight clusters, with a pinned provider
  version, single/multi-server topology, Cilium replacing the default CNI, and no
  arbitrary install-script surface.
- RKE2 -> `RKE2ExecutionSpec` for the hardened alternate production path, with a
  pinned provider version, HA server/agent roles, Cilium, secrets encryption,
  protected kernel defaults, and an explicit hardened-profile requirement.

Server membership comes from the Server Registry. Every server must have PASS SSH
preflight status and exactly one NodeRole assignment before a provisioning plan is
created. Provisioning creates a HIGH-risk ChangeSet and one exact-hash-bound provider
job per server.

## Cilium, Hubble, Radar and add-ons

Cilium is the network plugin contract and Hubble is the first-class network visibility
contract. The Hubble intelligence API accepts only aggregated operational summaries:
workload/namespace/service pairs, protocol/port counts, HTTP method/status-class
counts, RPS, bytes, drops/verdicts, latency quantiles and TCP-state counts. Raw
packet/flow payloads, authorization headers, secrets and unredacted L7 bodies are
outside the admitted AI/UI contract.

Radar is a first-class Kubernetes intelligence provider with AUTO/RADAR/NATIVE
context modes and Hermes-native UI/contracts. Its read contract covers resource and
application views, topology/neighborhood, issues/diagnosis, events/timeline/logs,
resource utilization and Prometheus discovery, Helm/GitOps history, audit/RBAC/TLS,
OpenCost, image/filesystem intelligence, CRD discovery, compare/diff and network
information. Radar write intent and MCP-style writes translate to normal Hermes
ChangeSets; no Radar UI is copied or iframed and no governance bypass exists.

The governed add-on catalog covers Cilium/Hubble, kube-vip, MetalLB, local-path or
Longhorn storage, ingress-nginx, cert-manager, Argo CD, Prometheus/Grafana/Loki,
OpenCost, Velero, Radar and the Hermes agent. All selected add-ons require explicit
version pins before a provisioning or add-on ChangeSet can be created.

## Day-2 foundations

`UpgradePlan` requires a typed staged plan with backup-before-upgrade sequencing.
`BackupPlan` includes retention/scope and restore-verification requirements. These
are plan/control foundations; provider-specific runtime execution remains constrained
by Hermes authorization and exact plan hashes.

Native read-only diagnostics cover node readiness, workload health, restart hotspots,
warning-event summaries, Hubble policy-drop summaries, storage/PVC health,
certificate expiry metadata and backup recency. `kubectl-aban-plugin` is not a
runtime dependency.

## Security invariant

Every infrastructure mutation remains:

`intent -> typed plan -> ChangeSet -> deterministic preview/diff -> risk -> policy -> approval -> exact-hash binding -> constrained execution ticket/provider job -> verification -> audit`

No LLM-facing component receives raw infrastructure credentials.
