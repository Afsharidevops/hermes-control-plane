# Cluster Factory

**Runtime-complete for existing registered servers, with provider execution disabled by default.** Cluster Factory produces governed provisioning plans for existing hosts; it is not a generic cluster installer and does not provide a capacity-backed create/destroy lifecycle.

## Resources

| Resource | Purpose |
|---|---|
| `ClusterBlueprint` | Declarative cluster shape, provider model, node-role requirements, offline dependencies, and addon selection. |
| `ClusterProfile` | Reusable operating profile and defaults. |
| `Cluster` | Desired/observed cluster record linked to a blueprint and provisioning lifecycle. |
| `NodeRole` | Exact role assignment for eligible pre-registered servers. |
| `ProvisioningRun` | Durable plan/job/evidence record for provider work. |
| `AddonPlan` | Catalogued addon selection and pins. |
| `UpgradePlan` | Typed cluster/provider upgrade intent. |
| `BackupPlan` | Typed backup/recovery intent. |

## Provisioning models and profiles

Supported provider models are `kubespray`, `k3s`, and `rke2`. Operational profiles are:

- `lab-minimal`
- `lab-full`
- `production`
- `production-ha`
- `production-hardened`

Select a profile only after reviewing provider/OS/network prerequisites. Profile selection does not make hardware, DNS, load balancing, certificate, or storage requirements disappear.

## Required flow

1. Register existing servers in **Cluster Factory → Servers** with safe inventory and a credential reference.
2. Use the sealed worker-side SSH profile to run preflight. Every assigned server must report **PASS**.
3. Define/reuse a `ClusterProfile`, then create a `ClusterBlueprint` with a supported provisioner, exact role counts, pinned addon/artifact requirements, and acceptable target constraints.
4. Assign exact `NodeRole` records to only PASS servers. No dynamic “pick any host” behavior is implied.
5. Resolve artifact dependencies and, for offline work, bind a READY exact artifact manifest.
6. Create a cluster/provisioning run. Hermes creates typed provider plan, ChangeSet, provider job, and durable provisioning record.
7. Request required approval and execute only after `HERMES_PROVIDER_EXECUTION_ENABLED=true` has been deliberately validated.
8. Review provider events and active verification; record handoff/maintenance state.

The provider worker uses fixed playbooks, private workspaces, configured PASS servers, exact typed-plan hashes, tickets, and replay prevention. It has no arbitrary shell, direct SSH host, copied-key, or user-supplied playbook interface.

## Addon catalog

The catalog includes Cilium/Hubble, kube-vip, MetalLB, storage choices, ingress-nginx, cert-manager, Argo CD, Prometheus/Grafana/Loki, OpenCost, Velero, Radar, and Hermes Agent. Selected addons require explicit version pins. Addons that involve Helm, GitOps, Cilium, backups, or recovery inherit their relevant Kubernetes ChangeSet constraints.

## Lifecycle capabilities

| Area | Availability | Boundary |
|---|---|---|
| Kubespray provisioning, worker lifecycle, upgrades, certificate rotation, maintenance | **Runtime-complete**, gate off | Existing registered/PASS hosts only. |
| K3s/RKE2 provisioning and embedded-etcd snapshot/restore/DR | **Runtime-complete**, gate off | Typed provider workflow with active verification. |
| Kubespray direct-etcd snapshot/restore/DR | Intentionally fails closed | No trusted runtime claim. |
| Capacity discovery/placement and capacity-backed lifecycle | **Contract-only/deferred** | Proxmox capacity signal does not prove placement or lifecycle. |
| Cloud/VMware/OpenStack backed Cluster Factory capacity | **Contract-only/deferred** | Provider descriptors are not trusted runtimes. |

## Offline installation

Use [Artifact mirroring](artifact-mirroring.md) to mirror exact needed items before a disconnected provisioning run. The blueprint dependency resolver produces a deterministic READY/BLOCKED manifest. Bind the exact READY manifest to the provisioning plan; a changed manifest requires a new plan/approval.

## Operational cautions

- Server preflight is not a hardware lifecycle or BMC validation.
- A provisioning run does not automatically roll back a partially changed cluster.
- Validate each provider/image combination on disposable hosts at the deployed image SHA before a production run.
- Protect private provider profile mount paths and worker data as credential-bearing operational assets.

See [Infrastructure providers](infrastructure-providers.md), [Governance](governance-and-changes.md), and [Kubernetes operations](kubernetes-operations.md).
