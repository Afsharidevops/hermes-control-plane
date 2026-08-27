# Infrastructure Providers and Node Agent

Node Agent is Hermes' boundary for existing-host cluster providers, infrastructure integrations, Proxmox collectors/runtime, and optional host observation. It runs with a read-only root filesystem, bounded temporary storage, read-only credential mounts, a worker token, and a signed-ticket validator. It is not a generic host-management agent.

## Evidence and gates

| Capability | Evidence | Required configuration |
|---|---|---|
| Existing-host Kubespray/K3s/RKE2 worker | **Runtime-complete** | `HERMES_PROVIDER_EXECUTION_ENABLED=true` after validation; sealed SSH profile mount; registered PASS servers. |
| Redfish, IPMI, PXE, host network, OpenConfig RESTCONF | **Integration/local evidence** | `HERMES_INFRASTRUCTURE_EXECUTION_ENABLED=true`, worker-side credentials and allowlists; retain `HERMES_INFRASTRUCTURE_ALLOW_HTTP=false`. |
| Proxmox capacity collector | **Integration/local evidence** | `HERMES_CAPACITY_COLLECTION_ENABLED=true`; read-only PVE capability allowlist. |
| Proxmox VM inventory | **Integration/local evidence** | `HERMES_VM_INVENTORY_COLLECTION_ENABLED=true`; sanitized read-only collection. |
| Proxmox QEMU runtime | **Integration/local evidence** | Both infrastructure and `HERMES_PROXMOX_VM_RUNTIME_ENABLED=true`; fixed capability allowlists. |
| VMware Workstation/VMware/OpenStack/AWS/Azure/GCP | **Contract-only/deferred** | Provider record/UI/contracts are not a trusted execution runtime. |

Local/mock tests do not establish real hardware/provider compatibility. Before a production enablement, validate the exact pushed image SHA on a disposable target and keep audit/verification evidence.

## Common worker controls

Every worker operation must have a typed plan, exact plan hash, signed one-time ticket, target/provider scope, gate, configured credential reference, capability allowlist, policy/approval result, bounded timeout, and active verification. Workers reject arbitrary shell commands, arbitrary SSH destinations, raw credentials, arbitrary transport paths/bodies, and ticket replay.

Credential files reside only in the worker's read-only mount. Paths such as `HERMES_PROVIDER_SSH_PROFILE_HOST_PATH` and `HERMES_INFRASTRUCTURE_CREDENTIAL_HOST_PATH` are sensitive deployment data and never belong in an API payload.

## Existing-host cluster provider operations

Kubespray supports governed provisioning, worker lifecycle, upgrades, certificate rotation, and maintenance. K3s and RKE2 support bounded embedded-etcd snapshot/restore/DR paths. Kubespray direct-etcd snapshot/restore/DR intentionally fails closed. See [Cluster Factory](cluster-factory.md) for the end-to-end flow.

## Redfish, IPMI, and PXE

### Redfish typed actions

```text
inventory.refresh
power.set
boot.set
boot-order.apply
secure-boot.apply
sriov.apply
iommu.apply
virtual-media.insert
virtual-media.eject
bios.apply
firmware.apply
storage.volume.apply
storage.volume.delete
```

Redfish transport is fixed to trusted endpoints with verified TLS, allowlisted capability sets, bounded request/verification loops, and secret-free evidence. Firmware/platform operations use longer but finite verification bounds.

### IPMI and PXE

IPMI permits only `power.set` and `boot.set`. PXE permits `os.provision` and `os.reimage`. They do not expose raw IPMI command execution, arbitrary boot scripts, arbitrary media URLs, or unrestricted host provisioning.

## Host network and OpenConfig RESTCONF

Host network contracts:

```text
interface.configure
interface.bond
vlan.configure
mtu.configure
address.configure
network.discover
```

The OpenConfig RESTCONF profile is `openconfig-restconf-v1`; it supports only `vlan.ensure`, `port.configure`, and `lldp.observe`. No free-form RESTCONF request is accepted.

### Host observer

The optional host observer uses a unique identity/token and read-only `/sys/class/net` and `/proc/net/vlan` access. It returns bounded interface state, MTU, bond count, and VLAN count with `PASS`, `SKIP`, or `FAIL`. It omits MAC/IP addresses, routes, DNS, raw files, environment, mount paths, tickets, secrets, shell, and CLI data.

## Proxmox

### Capacity and inventory collectors

Capacity collection is pinned to `pve-8.2 / pve-capacity-v1`, reads a fixed HTTPS PVE node-resource endpoint, and produces sanitized CPU/memory headroom for allowlisted nodes. It does **not** prove placement, scheduling, or a Cluster Factory capacity lifecycle.

VM inventory is pinned to `pve-8.2 / pve-vm-inventory-v1`, makes exactly two authenticated reads (nodes then VMs), and emits only:

```json
{
  "vm_id": 123,
  "node": "allowlisted-node",
  "type": "qemu|lxc",
  "power_state": "running|stopped",
  "template": false
}
```

It intentionally excludes VM names, tags, IPs, MACs, disks, storage, pool/owner details, raw payloads, endpoint data, and credentials.

### QEMU mutation runtime

The runtime allows exactly eight actions:

```text
vm.create
vm.clone
vm.update
vm.delete
vm.power
network.attach
snapshot.create
snapshot.restore
```

It supports QEMU only; LXC mutation is excluded. Transport, PVE paths, and request bodies are fixed; TLS is verified; redirects and ambient proxy are not permitted. Node, storage, bridge, template, action, and resource bounds are capability-allowlisted. Cloud-Init payloads, scripts, passthrough, QEMU arguments, IP/MAC fields, and raw PVE responses are excluded.

`vm.delete` and `snapshot.restore` are CRITICAL and require two distinct approvals. The remaining six actions are HIGH. No automatic rollback is provided. Preserve a tested recovery path and inspect active verification.

## Node Agent API

| Method | Route | Use |
|---|---|---|
| `GET` | `/health` | Worker health/capability state. |
| `POST` | `/v1/provider/preview` | Existing-host provider preview. |
| `POST` | `/v1/provider/execute` | Ticket-bound provider execution. |
| `POST` | `/v1/capacity/refresh` | Read-only capacity refresh. |
| `POST` | `/v1/vm/inventory/refresh` | Sanitized VM inventory refresh. |
| `POST` | `/v1/infrastructure/preview` | Infrastructure plan preview. |
| `POST` | `/v1/infrastructure/execute` | Ticket-bound bounded infrastructure execution. |

Host observer, when deployed independently, exposes `GET /health` and `POST /v1/collectors/host-network`.
