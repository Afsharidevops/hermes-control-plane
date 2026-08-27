from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

from .canonical import sha256_hex

MUTATION_GATE = "changeset-exact-hash-approval"

CLOUD_PROVIDER_CONTRACTS: dict[str, dict[str, Any]] = {
    "vmware": {
        "kind": "virtualization",
        "plan_contract": "VMwareResourcePlan",
        "credential_boundary": "credential-service-provider-worker-only",
        "required_pins": ["api_version", "implementation_version"],
        "actions": ["vm.create", "vm.update", "vm.delete", "vm.power", "vm.clone"],
    },
    "vmware-workstation": {
        "kind": "local-virtualization",
        "plan_contract": "VMwareWorkstationResourcePlan",
        "credential_boundary": "credential-service-provider-worker-only",
        "required_pins": ["api_version", "implementation_version"],
        "actions": ["vm.clone", "vm.update", "vm.delete", "vm.power", "network.attach"],
    },
    "proxmox": {
        "kind": "virtualization",
        "plan_contract": "ProxmoxResourcePlan",
        "credential_boundary": "credential-service-provider-worker-only",
        "required_pins": ["api_version", "implementation_version"],
        "actions": ["vm.create", "vm.clone", "vm.update", "vm.delete", "vm.power", "network.attach", "snapshot.create", "snapshot.restore"],
    },
    "openstack": {
        "kind": "cloud",
        "plan_contract": "OpenStackResourcePlan",
        "credential_boundary": "credential-service-provider-worker-only",
        "required_pins": ["api_version", "implementation_version"],
        "actions": ["vm.create", "vm.update", "vm.delete", "vm.power", "network.attach"],
    },
    "aws": {
        "kind": "cloud",
        "plan_contract": "AWSResourcePlan",
        "credential_boundary": "credential-service-provider-worker-only",
        "required_pins": ["api_version", "implementation_version"],
        "actions": ["vm.create", "vm.update", "vm.delete", "vm.power", "network.attach"],
    },
    "azure": {
        "kind": "cloud",
        "plan_contract": "AzureResourcePlan",
        "credential_boundary": "credential-service-provider-worker-only",
        "required_pins": ["api_version", "implementation_version"],
        "actions": ["vm.create", "vm.update", "vm.delete", "vm.power", "network.attach"],
    },
    "gcp": {
        "kind": "cloud",
        "plan_contract": "GCPResourcePlan",
        "credential_boundary": "credential-service-provider-worker-only",
        "required_pins": ["api_version", "implementation_version"],
        "actions": ["vm.create", "vm.update", "vm.delete", "vm.power", "network.attach"],
    },
}

BARE_METAL_PROVIDER_CONTRACTS: dict[str, dict[str, Any]] = {
    "redfish": {
        "kind": "bare-metal",
        "plan_contract": "RedfishBareMetalPlan",
        "credential_boundary": "credential-service-provider-worker-only",
        "actions": ["power.set", "boot.set", "boot-order.apply", "secure-boot.apply", "sriov.apply", "iommu.apply", "virtual-media.insert", "virtual-media.eject", "bios.apply", "firmware.apply", "storage.volume.apply", "storage.volume.delete", "inventory.refresh"],
        "arbitrary_command": False,
    },
    "ipmi": {
        "kind": "bare-metal-fallback",
        "plan_contract": "IPMIBareMetalPlan",
        "credential_boundary": "credential-service-provider-worker-only",
        "actions": ["power.set", "boot.set"],
        "arbitrary_command": False,
    },
    "pxe": {
        "kind": "os-provisioning",
        "plan_contract": "PXEProvisioningPlan",
        "credential_boundary": "credential-service-provider-worker-only",
        "actions": ["os.provision", "os.reimage", "os.recover", "os.decommission"],
        "arbitrary_install_script": False,
    },
    "host-network": {
        "kind": "host-networking",
        "plan_contract": "HostNetworkPlan",
        "credential_boundary": "credential-service-provider-worker-only",
        "actions": ["interface.configure", "interface.bond", "vlan.configure", "mtu.configure", "address.configure", "network.discover"],
        "arbitrary_command": False,
        "arbitrary_shell": False,
    },
}

NETWORK_PROVIDER_CONTRACTS: dict[str, dict[str, Any]] = {
    "network-switch": {
        "kind": "network-infrastructure",
        "plan_contract": "SwitchNetworkPlan",
        "credential_boundary": "credential-service-provider-worker-only",
        "actions": ["vlan.ensure", "port.configure", "bond.ensure", "network.attach", "network.detach", "lldp.observe", "bgp.configure"],
        "arbitrary_cli": False,
    }
}

INFRASTRUCTURE_RUNTIME_OPERATIONS: dict[str, set[str]] = {
    "redfish": {"inventory.refresh", "power.set", "boot.set", "boot-order.apply", "secure-boot.apply", "sriov.apply", "iommu.apply", "virtual-media.insert", "virtual-media.eject", "bios.apply", "firmware.apply", "storage.volume.apply", "storage.volume.delete"},
    "ipmi": {"power.set", "boot.set"},
    "pxe": {"os.provision", "os.reimage"},
    # Only provider kinds with a fully implemented trusted worker + active collector belong
    # here. Listing a kind makes the control plane dispatch to the infrastructure worker
    # instead of emitting a CONTRACT_ONLY plan, so virtualization/cloud kinds stay out.
    "host-network": {"interface.configure", "interface.bond", "vlan.configure", "mtu.configure", "address.configure", "network.discover"},
    "network-switch": {"vlan.ensure", "port.configure", "lldp.observe"},
    "proxmox": {"vm.create", "vm.clone", "vm.update", "vm.delete", "vm.power", "network.attach", "snapshot.create", "snapshot.restore"},
}
REDFISH_POWER_STATES = {"on", "force-off", "graceful-shutdown", "restart", "graceful-restart", "power-cycle"}
REDFISH_BOOT_TARGETS = {"pxe", "disk", "cd", "none"}
REDFISH_BOOT_ENABLED = {"once", "continuous", "disabled"}
REDFISH_BOOT_MODES = {"uefi", "legacy"}
REDFISH_BOOT_ORDER_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
REDFISH_PLATFORM_FEATURES = {"sriov", "iommu"}
REDFISH_PLATFORM_ACTIVATIONS = {"immediate", "reboot"}
REDFISH_RESET_TYPES = {"GracefulRestart", "ForceRestart"}
REDFISH_BIOS_ATTRIBUTE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
REDFISH_FIRMWARE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
REDFISH_STORAGE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$")
REDFISH_VOLUME_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{0,79}$")
REDFISH_RAID_TYPES = {"RAID0", "RAID1", "RAID5", "RAID6", "RAID10", "RAID50", "RAID60"}
IPMI_POWER_STATES = {"on", "force-off", "graceful-shutdown"}
IPMI_BOOT_TARGETS = {"pxe", "disk", "cd"}
IPMI_BOOT_ENABLED = {"once", "continuous"}
PXE_BOOT_METHODS = {"pxe", "ipxe"}
PXE_ARTIFACT_ROLES = {"kernel", "initrd", "rootfs", "installer", "unattended"}
PXE_REQUIRED_ARTIFACT_ROLES = {"kernel", "initrd", "unattended"}
PXE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$")
PXE_ARTIFACT_ID_RE = re.compile(r"^art_[A-Za-z0-9]{8,64}$")
PXE_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SWITCH_RESTCONF_PROFILE = "openconfig-restconf-v1"
SWITCH_RESTCONF_API_VERSION = "openconfig-restconf-1.0"
SWITCH_RESTCONF_IMPLEMENTATION_VERSION = "openconfig-restconf-v1"
SWITCH_PORT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,63}$")
SWITCH_VLAN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{0,63}$")
PROXMOX_VM_API_VERSION = "pve-8.2"
PROXMOX_VM_IMPLEMENTATION_VERSION = "pve-vm-runtime-v1"
PROXMOX_VM_OPERATIONS = {"vm.create", "vm.clone", "vm.update", "vm.delete", "vm.power", "network.attach", "snapshot.create", "snapshot.restore"}
PROXMOX_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
PROXMOX_SNAPSHOT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

ARTIFACT_KINDS = ("oci-image", "helm-chart", "package", "git-release", "ansible-collection", "apt-repository", "rpm-repository", "python-repository")

DAY2_OPERATIONS: dict[str, dict[str, Any]] = {
    "cluster.worker.add": {"kind": "WorkerLifecyclePlan", "stages": ["preflight", "snapshot", "join", "verify"]},
    "cluster.worker.remove": {"kind": "WorkerLifecyclePlan", "stages": ["preflight", "cordon", "drain", "remove", "verify"]},
    "cluster.worker.replace": {"kind": "WorkerLifecyclePlan", "stages": ["preflight", "add-replacement", "cordon", "drain", "remove-old", "verify"]},
    "cluster.node.cordon": {"kind": "NodeOperationPlan", "stages": ["preflight", "cordon", "verify"]},
    "cluster.node.uncordon": {"kind": "NodeOperationPlan", "stages": ["preflight", "uncordon", "verify"]},
    "cluster.node.drain": {"kind": "NodeOperationPlan", "stages": ["preflight", "cordon", "drain", "verify"]},
    "cluster.workload.restart": {"kind": "WorkloadOperationPlan", "stages": ["preflight", "restart", "rollout-verify"]},
    "cluster.workload.scale": {"kind": "WorkloadOperationPlan", "stages": ["preflight", "scale", "rollout-verify"]},
    "cluster.addon.install": {"kind": "AddonLifecyclePlan", "stages": ["preflight", "compatibility", "apply", "verify"]},
    "cluster.addon.upgrade": {"kind": "AddonLifecyclePlan", "stages": ["preflight", "backup", "compatibility", "upgrade", "verify"]},
    "cluster.helm.apply": {"kind": "HelmOperationPlan", "stages": ["preflight", "render", "diff", "apply", "verify"]},
    "cluster.gitops.sync": {"kind": "GitOpsOperationPlan", "stages": ["preflight", "render", "diff", "sync", "verify"]},
    "cluster.kubernetes.upgrade": {"kind": "KubernetesUpgradePlan", "stages": ["preflight", "backup", "control-plane", "workers", "addons", "verify"]},
    "cluster.cilium.upgrade": {"kind": "CiliumUpgradePlan", "stages": ["preflight", "backup", "upgrade", "cilium-verify", "hubble-verify"]},
    "cluster.backup.velero": {"kind": "VeleroBackupPlan", "stages": ["preflight", "create", "wait", "verify"]},
    "cluster.backup.schedule": {"kind": "VeleroSchedulePlan", "stages": ["preflight", "render", "upsert", "verify"]},
    "cluster.etcd.snapshot": {"kind": "EtcdSnapshotPlan", "stages": ["preflight", "snapshot", "integrity-verify"]},
    "cluster.etcd.restore": {"kind": "EtcdRestorePlan", "stages": ["preflight", "quorum-check", "restore", "restart", "integrity-verify"]},
    "cluster.restore": {"kind": "RestorePlan", "stages": ["preflight", "restore", "workload-verify", "network-verify"]},
    "cluster.certificate.rotate": {"kind": "CertificateRotationPlan", "stages": ["preflight", "rotate", "component-restart", "verify"]},
    "cluster.node.maintenance": {"kind": "NodeMaintenancePlan", "stages": ["preflight", "cordon", "drain", "maintenance", "verify", "uncordon"]},
    "cluster.decommission": {"kind": "ClusterDecommissionPlan", "stages": ["preflight", "final-backup", "workload-drain", "provider-destroy", "verify"]},
    "cluster.infrastructure.scale": {"kind": "InfrastructureScalePlan", "stages": ["preflight", "provider-plan", "scale", "reconcile", "verify"]},
    "cluster.template.clone": {"kind": "ClusterClonePlan", "stages": ["snapshot-source", "render-target", "provider-plan", "provision", "verify"]},
    "cluster.disaster-recovery": {"kind": "DisasterRecoveryPlan", "stages": ["preflight", "restore-control-plane", "restore-data", "reconcile-addons", "verify"]},
}

READ_OPERATIONS = {
    "inventory.list": "InventoryQuery",
    "health.status": "HealthQuery",
    "diagnostics.summary": "DiagnosticsQuery",
    "topology.read": "TopologyQuery",
    "network.live": "NetworkLiveQuery",
    "audit.read": "AuditQuery",
    "capacity.refresh": "ProviderCapacityQuery",
    "vm.inventory.refresh": "ProviderVmInventoryQuery",
}

# Capacity collection is intentionally staged. VMware Workstation has no supported
# remote collector; all unlisted providers remain contract-only for capacity too.
CAPACITY_PROVIDER_KINDS = {"proxmox"}
CAPACITY_PROVIDER_PINS = {"proxmox": ("pve-8.2", "pve-capacity-v1")}
VM_INVENTORY_PROVIDER_KINDS = {"proxmox"}
VM_INVENTORY_PROVIDER_PINS = {"proxmox": ("pve-8.2", "pve-vm-inventory-v1")}

KUBERNETES_DAY2_RUNTIME_OPERATIONS: dict[str, dict[str, Any]] = {
    "cluster.node.cordon": {"executor": "kubernetes-broker", "verification": ["node-unschedulable"]},
    "cluster.node.uncordon": {"executor": "kubernetes-broker", "verification": ["node-schedulable"]},
    "cluster.node.drain": {"executor": "kubernetes-broker", "verification": ["node-unschedulable", "drain-complete"]},
    "cluster.workload.restart": {"executor": "kubernetes-broker", "verification": ["rollout-complete"]},
    "cluster.workload.scale": {"executor": "kubernetes-broker", "verification": ["replicas-converged", "rollout-complete"]},
    "cluster.addon.install": {"executor": "kubernetes-broker", "verification": ["helm-release-ready"]},
    "cluster.addon.upgrade": {"executor": "kubernetes-broker", "verification": ["helm-release-ready"]},
    "cluster.helm.apply": {"executor": "kubernetes-broker", "verification": ["helm-release-ready"]},
    "cluster.gitops.sync": {"executor": "kubernetes-broker", "verification": ["gitops-synced", "gitops-healthy"]},
    "cluster.cilium.upgrade": {"executor": "kubernetes-broker", "verification": ["helm-release-ready", "cilium-ready", "hubble-ready"]},
    "cluster.backup.velero": {"executor": "kubernetes-broker", "verification": ["velero-backup-completed"]},
    "cluster.backup.schedule": {"executor": "kubernetes-broker", "verification": ["velero-schedule-ready"]},
    "cluster.restore": {"executor": "kubernetes-broker", "verification": ["velero-restore-source-bound", "velero-restore-completed"]},
}


def kubernetes_day2_runtime_capable(operation: str) -> bool:
    return operation in KUBERNETES_DAY2_RUNTIME_OPERATIONS


PROVIDER_DAY2_RUNTIME_OPERATIONS: dict[str, dict[str, Any]] = {
    "cluster.worker.add": {"verification": ["provider-active-verify", "offline-artifact-binding"]},
    "cluster.worker.remove": {"verification": ["provider-active-verify"]},
    "cluster.worker.replace": {"verification": ["provider-active-verify", "offline-artifact-binding"]},
    "cluster.kubernetes.upgrade": {"verification": ["provider-active-verify", "offline-artifact-binding"]},
    "cluster.etcd.snapshot": {"verification": ["provider-active-verify"]},
    "cluster.etcd.restore": {"verification": ["provider-active-verify"]},
    "cluster.certificate.rotate": {"verification": ["provider-active-verify"]},
    "cluster.node.maintenance": {"verification": ["provider-active-verify"]},
    "cluster.disaster-recovery": {"verification": ["provider-active-verify"]},
}


def provider_day2_runtime_capable(operation: str) -> bool:
    return operation in PROVIDER_DAY2_RUNTIME_OPERATIONS


def validate_provider_day2_parameters(operation: str, parameters: dict[str, Any]) -> None:
    if operation not in PROVIDER_DAY2_RUNTIME_OPERATIONS:
        raise ValueError(f"operation {operation} does not have a trusted cluster provider runtime executor")
    allowed_common = {"artifact_blueprint_id"}
    if operation == "cluster.worker.add":
        allowed = allowed_common | {"server_id"}
        if not str(parameters.get("server_id") or "").startswith("srv_"):
            raise ValueError("server_id is required for worker add")
    elif operation == "cluster.worker.remove":
        allowed = {"server_id"}
        if not str(parameters.get("server_id") or "").startswith("srv_"):
            raise ValueError("server_id is required for worker remove")
    elif operation == "cluster.worker.replace":
        allowed = allowed_common | {"old_server_id", "new_server_id"}
        if not str(parameters.get("old_server_id") or "").startswith("srv_") or not str(parameters.get("new_server_id") or "").startswith("srv_"):
            raise ValueError("old_server_id and new_server_id are required for worker replace")
        if parameters.get("old_server_id") == parameters.get("new_server_id"):
            raise ValueError("worker replacement requires distinct old/new servers")
    elif operation == "cluster.kubernetes.upgrade":
        allowed = {"target_version", "artifact_blueprint_id"}
        version = str(parameters.get("target_version") or "")
        import re
        if not re.fullmatch(r"v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", version):
            raise ValueError("target_version must be an explicit Kubernetes version")
        if not str(parameters.get("artifact_blueprint_id") or "").startswith("cbp_"):
            raise ValueError("artifact_blueprint_id is required for offline Kubernetes upgrade")
    elif operation in {"cluster.etcd.snapshot", "cluster.etcd.restore", "cluster.disaster-recovery"}:
        key = "snapshot_name" if operation == "cluster.etcd.snapshot" else "snapshot_reference"
        allowed = {key, "artifact_blueprint_id"} if operation == "cluster.disaster-recovery" else {key}
        import re
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}", str(parameters.get(key) or "")):
            raise ValueError(f"{key} must be a bounded snapshot identifier")
    elif operation == "cluster.certificate.rotate":
        allowed = set()
    elif operation == "cluster.node.maintenance":
        allowed = {"server_id", "action"}
        if not str(parameters.get("server_id") or "").startswith("srv_"):
            raise ValueError("server_id is required for provider-backed maintenance")
        if parameters.get("action") not in {"reboot", "restart-kubelet", "restart-provider-service"}:
            raise ValueError("maintenance action must be reboot, restart-kubelet or restart-provider-service")
    elif operation == "cluster.decommission":
        allowed = {"confirm_cluster_name"}
        if not str(parameters.get("confirm_cluster_name") or "").strip():
            raise ValueError("confirm_cluster_name is required for decommission")
    else:
        allowed = set()
    unknown = sorted(set(parameters) - allowed)
    if unknown:
        raise ValueError(f"unsupported provider day-2 parameter(s): {', '.join(unknown)}")


def _validate_velero_schedule_cron(value: str) -> str:
    cron = " ".join(str(value or "").split())
    if not cron or len(cron) > 80:
        raise ValueError("Velero schedule must be a bounded 5-field cron expression")
    fields = cron.split(" ")
    if len(fields) != 5:
        raise ValueError("Velero schedule must use exactly 5 cron fields")
    minute = fields[0]
    if not minute.isdigit() or not 0 <= int(minute) <= 59:
        raise ValueError("Velero schedule minute must be a fixed integer 0-59; schedules may run no more frequently than hourly")

    def valid_field(expr: str, low: int, high: int) -> bool:
        if not expr or len(expr) > 32:
            return False
        for item in expr.split(","):
            if not item:
                return False
            base, sep, step_text = item.partition("/")
            if sep:
                if not step_text.isdigit() or not 1 <= int(step_text) <= (high - low + 1) or "/" in step_text:
                    return False
            if base == "*":
                continue
            if "-" in base:
                first, dash, last = base.partition("-")
                if not dash or "-" in last or not first.isdigit() or not last.isdigit():
                    return False
                start, end = int(first), int(last)
                if start < low or end > high or start > end:
                    return False
            elif not base.isdigit() or not low <= int(base) <= high:
                return False
        return True

    for expr, low, high in zip(fields[1:], (0, 1, 1, 0), (23, 31, 12, 7)):
        if not valid_field(expr, low, high):
            raise ValueError("Velero schedule contains an unsupported or out-of-range cron field")
    return cron


def validate_kubernetes_day2_parameters(operation: str, parameters: dict[str, Any]) -> None:
    if operation not in KUBERNETES_DAY2_RUNTIME_OPERATIONS:
        raise ValueError(f"operation {operation} does not have a trusted Kubernetes Broker runtime executor")
    target_id = str(parameters.get("native_target_id") or "")
    if not target_id.startswith("tgt_"):
        raise ValueError("native_target_id referencing a configured Kubernetes target is required")
    if operation.startswith("cluster.node."):
        node = str(parameters.get("node") or "")
        if not node or len(node) > 253:
            raise ValueError("node is required for node lifecycle operations")
        if operation == "cluster.node.drain":
            for key in ("delete_emptydir_data", "force"):
                if key in parameters and not isinstance(parameters[key], bool):
                    raise ValueError(f"{key} must be boolean")
    elif operation in {"cluster.workload.restart", "cluster.workload.scale"}:
        kind = str(parameters.get("kind") or "").lower()
        if kind not in {"deployment", "statefulset", "daemonset"}:
            raise ValueError("kind must be deployment, statefulset, or daemonset")
        if operation == "cluster.workload.scale" and kind == "daemonset":
            raise ValueError("DaemonSets cannot be scaled with cluster.workload.scale")
        for key in ("name", "namespace"):
            if not str(parameters.get(key) or ""):
                raise ValueError(f"{key} is required for workload operations")
        if operation == "cluster.workload.scale":
            replicas = parameters.get("replicas")
            if not isinstance(replicas, int) or isinstance(replicas, bool) or replicas < 0 or replicas > 10000:
                raise ValueError("replicas must be an integer between 0 and 10000")
    elif operation == "cluster.gitops.sync":
        for key in ("application", "namespace", "revision"):
            if not str(parameters.get(key) or ""):
                raise ValueError(f"{key} is required for GitOps sync")
        revision = str(parameters.get("revision") or "")
        if len(revision) not in {40, 64} or any(ch not in "0123456789abcdefABCDEF" for ch in revision):
            raise ValueError("GitOps sync requires a full 40- or 64-character commit digest")
        if "prune" in parameters and not isinstance(parameters["prune"], bool):
            raise ValueError("prune must be boolean when provided")
    elif operation == "cluster.backup.velero":
        backup_name = str(parameters.get("backup_name") or "")
        if not backup_name or len(backup_name) > 253:
            raise ValueError("backup_name is required for Velero backup")
        namespace = str(parameters.get("namespace") or "velero")
        if not namespace or len(namespace) > 253:
            raise ValueError("namespace is required for Velero backup")
        included = parameters.get("included_namespaces", ["*"])
        excluded = parameters.get("excluded_namespaces", [])
        for key, value in (("included_namespaces", included), ("excluded_namespaces", excluded)):
            if not isinstance(value, list) or len(value) > 64 or any(not isinstance(item, str) or not item or len(item) > 253 for item in value):
                raise ValueError(f"{key} must be a list of at most 64 namespace names")
        if not included:
            raise ValueError("included_namespaces must contain at least one namespace or '*'")
        if "*" in included and len(included) != 1:
            raise ValueError("included_namespaces '*' must be used alone")
        if "*" in excluded:
            raise ValueError("excluded_namespaces cannot contain '*'")
        if "snapshot_volumes" in parameters and not isinstance(parameters["snapshot_volumes"], bool):
            raise ValueError("snapshot_volumes must be boolean when provided")
        ttl_hours = parameters.get("ttl_hours", 72)
        if not isinstance(ttl_hours, int) or isinstance(ttl_hours, bool) or ttl_hours < 1 or ttl_hours > 8760:
            raise ValueError("ttl_hours must be an integer between 1 and 8760")
    elif operation == "cluster.backup.schedule":
        schedule_name = str(parameters.get("schedule_name") or "")
        if not schedule_name or len(schedule_name) > 253:
            raise ValueError("schedule_name is required for Velero schedule")
        namespace = str(parameters.get("namespace") or "velero")
        if not namespace or len(namespace) > 253:
            raise ValueError("namespace is required for Velero schedule")
        _validate_velero_schedule_cron(str(parameters.get("schedule") or ""))
        included = parameters.get("included_namespaces", ["*"])
        excluded = parameters.get("excluded_namespaces", [])
        for key, value in (("included_namespaces", included), ("excluded_namespaces", excluded)):
            if not isinstance(value, list) or len(value) > 64 or any(not isinstance(item, str) or not item or len(item) > 253 for item in value):
                raise ValueError(f"{key} must be a list of at most 64 namespace names")
        if not included:
            raise ValueError("included_namespaces must contain at least one namespace or '*'")
        if "*" in included and len(included) != 1:
            raise ValueError("included_namespaces '*' must be used alone")
        if "*" in excluded:
            raise ValueError("excluded_namespaces cannot contain '*'")
        if "snapshot_volumes" in parameters and not isinstance(parameters["snapshot_volumes"], bool):
            raise ValueError("snapshot_volumes must be boolean when provided")
        ttl_hours = parameters.get("ttl_hours", 72)
        if not isinstance(ttl_hours, int) or isinstance(ttl_hours, bool) or ttl_hours < 1 or ttl_hours > 8760:
            raise ValueError("ttl_hours must be an integer between 1 and 8760")
    elif operation == "cluster.restore":
        for key in ("restore_name", "backup_name"):
            value = str(parameters.get(key) or "")
            if not value or len(value) > 253:
                raise ValueError(f"{key} is required for Velero restore")
        namespace = str(parameters.get("namespace") or "velero")
        if not namespace or len(namespace) > 253:
            raise ValueError("namespace is required for Velero restore")
        included = parameters.get("included_namespaces")
        if not isinstance(included, list) or not included or len(included) > 32:
            raise ValueError("included_namespaces must contain 1-32 explicit namespaces for Velero restore")
        if any(not isinstance(item, str) or not item or len(item) > 253 or item == "*" for item in included):
            raise ValueError("Velero restore requires explicit namespace names; '*' is not allowed")
        if len(set(included)) != len(included):
            raise ValueError("included_namespaces must not contain duplicates")
        if "restore_pvs" in parameters and not isinstance(parameters["restore_pvs"], bool):
            raise ValueError("restore_pvs must be boolean when provided")
    else:
        for key in ("release", "chart", "namespace", "version"):
            if not str(parameters.get(key) or ""):
                raise ValueError(f"{key} is required for Helm-backed day-2 operations")
        if str(parameters.get("version")) in {"latest", "*"}:
            raise ValueError("Helm-backed day-2 operations require an explicit pinned version")
        if operation == "cluster.cilium.upgrade":
            if str(parameters.get("release")) != "cilium":
                raise ValueError("Cilium upgrade requires release=cilium")
            if str(parameters.get("namespace")) != "kube-system":
                raise ValueError("Cilium upgrade requires namespace=kube-system")
            if "cilium" not in str(parameters.get("chart") or "").lower():
                raise ValueError("Cilium upgrade requires a Cilium Helm chart reference")
        values_yaml = parameters.get("values_yaml")
        if values_yaml is not None and not isinstance(values_yaml, str):
            raise ValueError("values_yaml must be a string when provided")


VERIFICATION_CHECKS = [
    "hosts",
    "networking",
    "etcd",
    "api-server",
    "nodes",
    "cilium",
    "hubble",
    "dns",
    "storage",
    "ingress-tls",
    "gitops",
    "observability",
    "radar",
    "hermes-agent",
    "baseline-security",
]


def _finish(plan: dict[str, Any]) -> dict[str, Any]:
    plan["plan_hash"] = sha256_hex(plan)
    return plan


def read_query_plan(*, operation: str, selector: dict[str, Any], parameters: dict[str, Any]) -> dict[str, Any]:
    if operation not in READ_OPERATIONS:
        raise ValueError(f"unsupported read operation: {operation}")
    return _finish({
        "schema_version": 4,
        "kind": READ_OPERATIONS[operation],
        "operation": operation,
        "mode": "read",
        "selector": selector,
        "parameters": parameters,
        "authorization": "required",
        "credential_material": "forbidden",
    })


def validate_capacity_provider(provider_snapshot: dict[str, Any]) -> None:
    kind = str(provider_snapshot.get("kind") or "")
    if kind not in CAPACITY_PROVIDER_KINDS:
        raise ValueError("provider does not have a supported live capacity collector")
    if provider_snapshot.get("status") != "configured":
        raise ValueError("capacity provider must be configured")
    if (str(provider_snapshot.get("api_version") or ""), str(provider_snapshot.get("implementation_version") or "")) != CAPACITY_PROVIDER_PINS[kind]:
        raise ValueError("capacity provider versions do not match the supported collector profile")
    endpoint = str(provider_snapshot.get("endpoint") or "")
    parsed = urlparse(endpoint)
    if (
        parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
        or parsed.password is not None or parsed.query or parsed.fragment or parsed.port != 8006
        or parsed.path.rstrip("/") != "/api2/json"
    ):
        raise ValueError("Proxmox capacity endpoint must be credential-free HTTPS on port 8006 with /api2/json root")
    caps = provider_snapshot.get("capabilities")
    nodes = caps.get("node_allowlist") if isinstance(caps, dict) else None
    if set(caps or {}) != {"node_allowlist"} or not isinstance(nodes, list) or not 1 <= len(nodes) <= 32:
        raise ValueError("Proxmox capacity requires a bounded node_allowlist capability")
    normalized = [str(node) for node in nodes]
    if len(set(normalized)) != len(normalized) or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", node) for node in normalized):
        raise ValueError("Proxmox capacity node_allowlist contains unsafe or duplicate nodes")
    credential = provider_snapshot.get("credential_snapshot")
    if not isinstance(credential, dict) or credential.get("status") != "configured":
        raise ValueError("capacity provider credential reference must be configured")
    if credential.get("id") != provider_snapshot.get("credential_ref"):
        raise ValueError("capacity provider credential snapshot does not match its reference")
    snapshot_hash = provider_snapshot.get("snapshot_hash")
    unsigned = dict(provider_snapshot)
    unsigned.pop("snapshot_hash", None)
    if not isinstance(snapshot_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", snapshot_hash) or sha256_hex(unsigned) != snapshot_hash:
        raise ValueError("capacity provider snapshot hash is invalid")


def capacity_query_plan(*, provider_snapshot: dict[str, Any]) -> dict[str, Any]:
    validate_capacity_provider(provider_snapshot)
    return _finish({
        "schema_version": 1,
        "kind": "ProviderCapacityQuery",
        "operation": "capacity.refresh",
        "mode": "read",
        "provider": provider_snapshot,
        "read_only": True,
        "live_upstream_required": True,
        "credential_material_in_plan": False,
        "mutation_runtime": "CONTRACT_ONLY",
        "authorization": "required",
    })


def validate_vm_inventory_provider(provider_snapshot: dict[str, Any]) -> None:
    kind = str(provider_snapshot.get("kind") or "")
    if kind not in VM_INVENTORY_PROVIDER_KINDS:
        raise ValueError("provider does not have a supported live VM inventory collector")
    if provider_snapshot.get("status") != "configured":
        raise ValueError("VM inventory provider must be configured")
    if (str(provider_snapshot.get("api_version") or ""), str(provider_snapshot.get("implementation_version") or "")) != VM_INVENTORY_PROVIDER_PINS[kind]:
        raise ValueError("VM inventory provider versions do not match the supported collector profile")
    endpoint = str(provider_snapshot.get("endpoint") or "")
    parsed = urlparse(endpoint)
    if (
        parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
        or parsed.password is not None or parsed.query or parsed.fragment or parsed.port != 8006
        or parsed.path.rstrip("/") != "/api2/json"
    ):
        raise ValueError("Proxmox VM inventory endpoint must be credential-free HTTPS on port 8006 with /api2/json root")
    caps = provider_snapshot.get("capabilities")
    nodes = caps.get("node_allowlist") if isinstance(caps, dict) else None
    if set(caps or {}) != {"node_allowlist"} or not isinstance(nodes, list) or not 1 <= len(nodes) <= 32:
        raise ValueError("Proxmox VM inventory requires a bounded node_allowlist capability")
    normalized = [str(node) for node in nodes]
    if len(set(normalized)) != len(normalized) or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", node) for node in normalized):
        raise ValueError("Proxmox VM inventory node_allowlist contains unsafe or duplicate nodes")
    credential = provider_snapshot.get("credential_snapshot")
    if not isinstance(credential, dict) or credential.get("status") != "configured":
        raise ValueError("VM inventory provider credential reference must be configured")
    if credential.get("id") != provider_snapshot.get("credential_ref"):
        raise ValueError("VM inventory provider credential snapshot does not match its reference")
    snapshot_hash = provider_snapshot.get("snapshot_hash")
    unsigned = dict(provider_snapshot)
    unsigned.pop("snapshot_hash", None)
    if not isinstance(snapshot_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", snapshot_hash) or sha256_hex(unsigned) != snapshot_hash:
        raise ValueError("VM inventory provider snapshot hash is invalid")


def vm_inventory_query_plan(*, provider_snapshot: dict[str, Any]) -> dict[str, Any]:
    validate_vm_inventory_provider(provider_snapshot)
    return _finish({
        "schema_version": 1,
        "kind": "ProviderVmInventoryQuery",
        "operation": "vm.inventory.refresh",
        "mode": "read",
        "provider": provider_snapshot,
        "read_only": True,
        "live_upstream_required": True,
        "credential_material_in_plan": False,
        "mutation_runtime": "CONTRACT_ONLY",
        "authorization": "required",
    })


def day2_plan(*, operation: str, targets: list[dict[str, Any]], parameters: dict[str, Any], runtime_preview: dict[str, Any] | None = None, artifact_supply: dict[str, Any] | None = None) -> dict[str, Any]:
    contract = DAY2_OPERATIONS.get(operation)
    if not contract:
        raise ValueError(f"unsupported day-2 operation: {operation}")
    plan = {
        "schema_version": 5,
        "kind": contract["kind"],
        "operation": operation,
        "targets": targets,
        "parameters": parameters,
        "runtime_preview": runtime_preview,
        "stages": contract["stages"],
        "verification_required": True,
        "mutation_gate": MUTATION_GATE,
        "arbitrary_shell": False,
    }
    if artifact_supply is not None:
        plan["artifact_supply"] = artifact_supply
    return _finish(plan)


def fleet_plan(*, operation: str, selector: dict[str, Any], targets: list[dict[str, Any]], parameters: dict[str, Any]) -> dict[str, Any]:
    if operation not in DAY2_OPERATIONS:
        raise ValueError(f"unsupported fleet operation: {operation}")
    if not targets:
        raise ValueError("fleet selector matched no clusters")
    return _finish({
        "schema_version": 4,
        "kind": "FleetOperationPlan",
        "operation": operation,
        "selector": selector,
        "targets": targets,
        "exact_target_count": len(targets),
        "parameters": parameters,
        "per_target_contract": DAY2_OPERATIONS[operation],
        "target_drift_policy": "reject-on-snapshot-change",
        "verification_required": True,
        "mutation_gate": MUTATION_GATE,
    })


def infrastructure_runtime_operation_capable(provider_kind: str, operation: str) -> bool:
    return operation in INFRASTRUCTURE_RUNTIME_OPERATIONS.get(provider_kind, set())


def _proxmox_integer(value: Any, *, field: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise ValueError(f"Proxmox {field} must be an integer between {low} and {high}")
    return value


def _proxmox_identifier(value: Any, *, field: str) -> str:
    normalized = str(value or "")
    if not PROXMOX_ID_RE.fullmatch(normalized):
        raise ValueError(f"Proxmox {field} is unsafe")
    return normalized


def _validate_proxmox_vm_desired_state(operation: str, desired: dict[str, Any]) -> None:
    if operation not in PROXMOX_VM_OPERATIONS:
        raise ValueError("unsupported Proxmox VM runtime operation")
    if operation == "vm.create":
        required = {"vm_id", "node", "name", "cpu_cores", "memory_mib", "storage", "disk_gib"}
        if not required <= set(desired) or set(desired) - (required | {"bridge"}):
            raise ValueError("Proxmox vm.create requires exact bounded QEMU fields")
        _proxmox_integer(desired.get("vm_id"), field="vm_id", low=100, high=2_147_483_647)
        for field in ("node", "name", "storage"):
            _proxmox_identifier(desired.get(field), field=field)
        if "bridge" in desired:
            _proxmox_identifier(desired["bridge"], field="bridge")
        _proxmox_integer(desired.get("cpu_cores"), field="cpu_cores", low=1, high=128)
        _proxmox_integer(desired.get("memory_mib"), field="memory_mib", low=512, high=1_048_576)
        _proxmox_integer(desired.get("disk_gib"), field="disk_gib", low=8, high=65_536)
        return
    if operation == "vm.clone":
        if set(desired) != {"source_vm_id", "source_node", "target_vm_id", "target_node", "storage", "name"}:
            raise ValueError("Proxmox vm.clone requires exact source/target fields")
        for field in ("source_node", "target_node", "storage", "name"):
            _proxmox_identifier(desired.get(field), field=field)
        for field in ("source_vm_id", "target_vm_id"):
            _proxmox_integer(desired.get(field), field=field, low=100, high=2_147_483_647)
        return
    if operation == "vm.update":
        if not {"vm_id", "node"} <= set(desired) or set(desired) - {"vm_id", "node", "cpu_cores", "memory_mib", "onboot"} or len(desired) == 2:
            raise ValueError("Proxmox vm.update requires VM identity plus at least one supported setting")
        _proxmox_integer(desired.get("vm_id"), field="vm_id", low=100, high=2_147_483_647)
        _proxmox_identifier(desired.get("node"), field="node")
        if "cpu_cores" in desired:
            _proxmox_integer(desired["cpu_cores"], field="cpu_cores", low=1, high=128)
        if "memory_mib" in desired:
            _proxmox_integer(desired["memory_mib"], field="memory_mib", low=512, high=1_048_576)
        if "onboot" in desired and not isinstance(desired["onboot"], bool):
            raise ValueError("Proxmox onboot must be boolean")
        return
    if operation in {"vm.delete", "vm.power"}:
        expected = {"vm_id", "node", "confirm_vm_id"} if operation == "vm.delete" else {"vm_id", "node", "target_state"}
        if set(desired) != expected:
            raise ValueError(f"Proxmox {operation} has unsupported fields")
        vm_id = _proxmox_integer(desired.get("vm_id"), field="vm_id", low=100, high=2_147_483_647)
        _proxmox_identifier(desired.get("node"), field="node")
        if operation == "vm.delete" and desired.get("confirm_vm_id") != vm_id:
            raise ValueError("Proxmox VM delete confirmation must exactly match vm_id")
        if operation == "vm.power" and str(desired.get("target_state") or "").lower() not in {"running", "stopped"}:
            raise ValueError("Proxmox vm.power target_state must be running or stopped")
        return
    if operation == "network.attach":
        if set(desired) != {"vm_id", "node", "slot", "bridge"}:
            raise ValueError("Proxmox network.attach requires exact VM, slot and bridge fields")
        _proxmox_integer(desired.get("vm_id"), field="vm_id", low=100, high=2_147_483_647)
        for field in ("node", "bridge"):
            _proxmox_identifier(desired.get(field), field=field)
        if str(desired.get("slot") or "") not in {f"net{index}" for index in range(8)}:
            raise ValueError("Proxmox network.attach slot must be net0 through net7")
        return
    expected = {"vm_id", "node", "snapshot"} if operation == "snapshot.create" else {"vm_id", "node", "snapshot", "confirm_vm_id", "confirm_snapshot"}
    if set(desired) != expected:
        raise ValueError(f"Proxmox {operation} has unsupported fields")
    vm_id = _proxmox_integer(desired.get("vm_id"), field="vm_id", low=100, high=2_147_483_647)
    _proxmox_identifier(desired.get("node"), field="node")
    snapshot = str(desired.get("snapshot") or "")
    if not PROXMOX_SNAPSHOT_RE.fullmatch(snapshot):
        raise ValueError("Proxmox snapshot name is unsafe")
    if operation == "snapshot.restore" and (desired.get("confirm_vm_id") != vm_id or desired.get("confirm_snapshot") != snapshot):
        raise ValueError("Proxmox snapshot restore confirmations must exactly match vm_id and snapshot")


def validate_infrastructure_desired_state(provider_kind: str, operation: str, desired_state: dict[str, Any]) -> None:
    if not infrastructure_runtime_operation_capable(provider_kind, operation):
        return
    if provider_kind == "proxmox":
        _validate_proxmox_vm_desired_state(operation, desired_state)
        return
    if provider_kind == "ipmi":
        if operation == "power.set":
            if set(desired_state) != {"state"}:
                raise ValueError("IPMI power.set requires only desired_state.state")
            if str(desired_state.get("state") or "").lower() not in IPMI_POWER_STATES:
                raise ValueError("unsupported IPMI power state")
            return
        allowed = {"target", "enabled", "mode"}
        unknown = sorted(set(desired_state) - allowed)
        if unknown:
            raise ValueError("unsupported IPMI boot desired_state field(s): " + ", ".join(unknown))
        if str(desired_state.get("target") or "").lower() not in IPMI_BOOT_TARGETS:
            raise ValueError("unsupported IPMI boot target")
        if str(desired_state.get("enabled") or "once").lower() not in IPMI_BOOT_ENABLED:
            raise ValueError("unsupported IPMI boot enable mode")
        mode = str(desired_state.get("mode") or "").lower()
        if mode and mode not in REDFISH_BOOT_MODES:
            raise ValueError("unsupported IPMI boot mode")
        return
    if provider_kind == "pxe":
        allowed = {
            "boot_method", "artifacts", "unattended_profile_ref", "callback_ref", "callback_token_sha256",
            "completion_timeout_seconds", "host_ready_timeout_seconds", "boot_mode", "confirm_server",
        }
        unknown = sorted(set(desired_state) - allowed)
        if unknown:
            raise ValueError("unsupported PXE desired_state field(s): " + ", ".join(unknown))
        boot_method = str(desired_state.get("boot_method") or "").lower()
        if boot_method not in PXE_BOOT_METHODS:
            raise ValueError("PXE boot_method must be pxe or ipxe")
        boot_mode = str(desired_state.get("boot_mode") or "uefi").lower()
        if boot_mode not in REDFISH_BOOT_MODES:
            raise ValueError("PXE boot_mode must be uefi or legacy")
        artifacts = desired_state.get("artifacts")
        if not isinstance(artifacts, dict):
            raise ValueError("PXE desired_state.artifacts must be an object")
        unknown_roles = sorted(set(artifacts) - PXE_ARTIFACT_ROLES)
        if unknown_roles:
            raise ValueError("unsupported PXE artifact role(s): " + ", ".join(unknown_roles))
        missing_roles = sorted(PXE_REQUIRED_ARTIFACT_ROLES - set(artifacts))
        if missing_roles:
            raise ValueError("PXE artifacts require: " + ", ".join(missing_roles))
        if len(set(str(value) for value in artifacts.values())) != len(artifacts):
            raise ValueError("PXE artifact IDs must be unique across roles")
        for artifact_id in artifacts.values():
            if not PXE_ARTIFACT_ID_RE.fullmatch(str(artifact_id or "")):
                raise ValueError("PXE artifacts must reference exact artifact mirror IDs")
        for field in ("unattended_profile_ref", "callback_ref"):
            if not PXE_REF_RE.fullmatch(str(desired_state.get(field) or "")):
                raise ValueError(f"PXE {field} is invalid")
        if not PXE_SHA256_RE.fullmatch(str(desired_state.get("callback_token_sha256") or "")):
            raise ValueError("PXE callback_token_sha256 must be an exact lowercase SHA-256 digest")
        completion = desired_state.get("completion_timeout_seconds", 3600)
        host_ready = desired_state.get("host_ready_timeout_seconds", 300)
        if not isinstance(completion, int) or isinstance(completion, bool) or not 60 <= completion <= 7200:
            raise ValueError("PXE completion_timeout_seconds must be between 60 and 7200")
        if not isinstance(host_ready, int) or isinstance(host_ready, bool) or not 10 <= host_ready <= 900:
            raise ValueError("PXE host_ready_timeout_seconds must be between 10 and 900")
        confirm = str(desired_state.get("confirm_server") or "")
        if operation == "os.reimage" and not confirm:
            raise ValueError("PXE os.reimage requires confirm_server")
        if operation == "os.provision" and confirm:
            raise ValueError("PXE os.provision does not accept confirm_server")
        return
    if provider_kind == "host-network":
        NETWORK_INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
        NETWORK_MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
        NETWORK_VLAN_RE = re.compile(r"^[1-9][0-9]{0,3}$|^[1-5][0-9]{4}$|^6[0-4][0-9]{3}$|^65[0-4][0-9][0-9]$|^655[0-2][0-9]$|^6553[0-5]$")
        NETWORK_MTU_RE = re.compile(r"^([6-9][0-9]{2,3}|1[0-8][0-9]{2}|19[0-9]{2}|20[0-9]{2}|21[0-9]{2}|22[0-9]{2}|9[0-9]{3}|[1-8][0-9]{4})$")
        if operation == "network.discover":
            if desired_state:
                raise ValueError("host-network network.discover does not accept desired_state fields")
            return
        if operation == "interface.configure":
            allowed = {"interface", "mac", "state", "mtu"}
            unknown = sorted(set(desired_state) - allowed)
            if unknown:
                raise ValueError("unsupported host-network interface.configure field(s): " + ", ".join(unknown))
            interface = str(desired_state.get("interface") or "")
            if not NETWORK_INTERFACE_RE.fullmatch(interface):
                raise ValueError("host-network interface name is invalid")
            if "mac" in desired_state:
                mac = str(desired_state["mac"] or "").lower()
                if not NETWORK_MAC_RE.fullmatch(mac):
                    raise ValueError("host-network MAC address is invalid")
            if "state" in desired_state:
                if str(desired_state["state"] or "").lower() not in {"up", "down"}:
                    raise ValueError("host-network interface state must be up or down")
            if "mtu" in desired_state:
                mtu = str(desired_state["mtu"] or "")
                if not NETWORK_MTU_RE.fullmatch(mtu):
                    raise ValueError("host-network MTU is invalid")
            return
        if operation == "interface.bond":
            allowed = {"bond_interface", "mode", "slaves", "miimon", "lacp_rate"}
            unknown = sorted(set(desired_state) - allowed)
            if unknown:
                raise ValueError("unsupported host-network interface.bond field(s): " + ", ".join(unknown))
            bond = str(desired_state.get("bond_interface") or "")
            if not NETWORK_INTERFACE_RE.fullmatch(bond) or not bond.startswith("bond"):
                raise ValueError("host-network bond interface name must start with 'bond'")
            mode = str(desired_state.get("mode") or "802.3ad").lower()
            if mode not in {"802.3ad", "active-backup", "balance-tlb", "balance-alb", "balance-rr", "balance-xor", "broadcast"}:
                raise ValueError("host-network bond mode must be a supported bonding mode")
            slaves = desired_state.get("slaves")
            if not isinstance(slaves, list) or not 1 <= len(slaves) <= 16:
                raise ValueError("host-network bond requires between 1 and 16 slave interfaces")
            for slave in slaves:
                if not NETWORK_INTERFACE_RE.fullmatch(str(slave or "")):
                    raise ValueError("host-network bond slave interface name is invalid")
            return
        if operation == "vlan.configure":
            allowed = {"interface", "vlan_id"}
            unknown = sorted(set(desired_state) - allowed)
            if unknown:
                raise ValueError("unsupported host-network vlan.configure field(s): " + ", ".join(unknown))
            vlan_id = str(desired_state.get("vlan_id") or "")
            interface = str(desired_state.get("interface") or "")
            if not NETWORK_INTERFACE_RE.fullmatch(interface):
                raise ValueError("host-network vlan interface name is invalid")
            if not NETWORK_VLAN_RE.fullmatch(vlan_id):
                raise ValueError("host-network vlan_id must be a valid VLAN ID (1-4094)")
            return
        if operation == "mtu.configure":
            allowed = {"interface", "mtu"}
            unknown = sorted(set(desired_state) - allowed)
            if unknown:
                raise ValueError("unsupported host-network mtu.configure field(s): " + ", ".join(unknown))
            mtu = str(desired_state.get("mtu") or "")
            interface = str(desired_state.get("interface") or "")
            if not NETWORK_INTERFACE_RE.fullmatch(interface):
                raise ValueError("host-network mtu interface name is invalid")
            if not NETWORK_MTU_RE.fullmatch(mtu):
                raise ValueError("host-network MTU is invalid")
            return
        if operation == "address.configure":
            allowed = {"interface", "address", "prefix", "gateway", "dns"}
            unknown = sorted(set(desired_state) - allowed)
            if unknown:
                raise ValueError("unsupported host-network address.configure field(s): " + ", ".join(unknown))
            import ipaddress
            address = str(desired_state.get("address") or "")
            interface = str(desired_state.get("interface") or "")
            if not NETWORK_INTERFACE_RE.fullmatch(interface):
                raise ValueError("host-network address interface name is invalid")
            try:
                ipaddress.ip_address(address)
            except ValueError as exc:
                raise ValueError("host-network address is not a valid IP address") from exc
            prefix = desired_state.get("prefix")
            if prefix is not None:
                if not isinstance(prefix, int) or isinstance(prefix, bool) or not 1 <= prefix <= 128:
                    raise ValueError("host-network prefix must be between 1 and 128")
            if "gateway" in desired_state:
                gw = str(desired_state["gateway"] or "")
                try:
                    ipaddress.ip_address(gw)
                except ValueError as exc:
                    raise ValueError("host-network gateway is not a valid IP address") from exc
            if "dns" in desired_state:
                dns = desired_state["dns"]
                if not isinstance(dns, list) or len(dns) > 4:
                    raise ValueError("host-network dns must be a list of up to 4 addresses")
                for dns_entry in dns:
                    try:
                        ipaddress.ip_address(str(dns_entry or ""))
                    except ValueError as exc:
                        raise ValueError("host-network dns entry is not a valid IP address") from exc
            return
        return
    if provider_kind == "network-switch":
        if operation == "lldp.observe":
            if desired_state:
                raise ValueError("network-switch lldp.observe does not accept desired_state fields")
            return
        if operation == "vlan.ensure":
            if set(desired_state) != {"vlan_id", "name"}:
                raise ValueError("network-switch vlan.ensure requires only vlan_id and name")
            vlan_id = desired_state.get("vlan_id")
            if not isinstance(vlan_id, int) or isinstance(vlan_id, bool) or not 1 <= vlan_id <= 4094:
                raise ValueError("network-switch vlan_id must be an integer between 1 and 4094")
            name = str(desired_state.get("name") or "")
            if not SWITCH_VLAN_NAME_RE.fullmatch(name):
                raise ValueError("network-switch VLAN name is unsafe")
            return
        if operation == "port.configure":
            allowed = {"port", "mode", "access_vlan", "trunk_vlans"}
            unknown = sorted(set(desired_state) - allowed)
            if unknown:
                raise ValueError("unsupported network-switch port.configure field(s): " + ", ".join(unknown))
            port = str(desired_state.get("port") or "")
            mode = str(desired_state.get("mode") or "").lower()
            if not SWITCH_PORT_RE.fullmatch(port):
                raise ValueError("network-switch port identifier is unsafe")
            if mode == "access":
                if set(desired_state) != {"port", "mode", "access_vlan"}:
                    raise ValueError("network-switch access port requires only port, mode and access_vlan")
                vlan_id = desired_state.get("access_vlan")
                if not isinstance(vlan_id, int) or isinstance(vlan_id, bool) or not 1 <= vlan_id <= 4094:
                    raise ValueError("network-switch access_vlan must be an integer between 1 and 4094")
                return
            if mode == "trunk":
                if set(desired_state) != {"port", "mode", "trunk_vlans"}:
                    raise ValueError("network-switch trunk port requires only port, mode and trunk_vlans")
                vlan_ids = desired_state.get("trunk_vlans")
                if not isinstance(vlan_ids, list) or not 1 <= len(vlan_ids) <= 64:
                    raise ValueError("network-switch trunk_vlans must contain between 1 and 64 VLAN IDs")
                if any(not isinstance(item, int) or isinstance(item, bool) or not 1 <= item <= 4094 for item in vlan_ids):
                    raise ValueError("network-switch trunk_vlans must contain VLAN IDs between 1 and 4094")
                if len(set(vlan_ids)) != len(vlan_ids):
                    raise ValueError("network-switch trunk_vlans must be unique")
                return
            raise ValueError("network-switch port mode must be access or trunk")
    if provider_kind in {"proxmox", "vmware-workstation", "vmware", "openstack", "aws", "azure", "gcp"}:
        return
    if provider_kind != "redfish":
        return
    if operation == "inventory.refresh":
        if desired_state:
            raise ValueError("Redfish inventory.refresh does not accept desired_state fields")
        return
    if operation == "power.set":
        if set(desired_state) != {"state"}:
            raise ValueError("Redfish power.set requires only desired_state.state")
        if str(desired_state.get("state") or "").lower() not in REDFISH_POWER_STATES:
            raise ValueError("unsupported Redfish power state")
        return
    if operation == "virtual-media.eject":
        if desired_state:
            raise ValueError("Redfish virtual-media.eject does not accept desired_state fields")
        return
    if operation == "virtual-media.insert":
        allowed = {"image_url", "write_protected"}
        unknown = sorted(set(desired_state) - allowed)
        if unknown:
            raise ValueError("unsupported Redfish virtual-media.insert desired_state field(s): " + ", ".join(unknown))
        image_url = str(desired_state.get("image_url") or "")
        parsed = urlparse(image_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise ValueError("Redfish virtual media image_url must be credential-free HTTPS without query/fragment")
        if desired_state.get("write_protected", True) is not True:
            raise ValueError("Redfish virtual media must be write-protected")
        return
    if operation == "secure-boot.apply":
        if set(desired_state) != {"enabled", "activation"}:
            raise ValueError("Redfish secure-boot.apply requires enabled and activation")
        if not isinstance(desired_state.get("enabled"), bool):
            raise ValueError("Redfish secure boot enabled must be boolean")
        if str(desired_state.get("activation") or "").lower() != "reboot":
            raise ValueError("Redfish SecureBootEnable is activated on reboot; activation must be reboot")
        return
    if operation in {"sriov.apply", "iommu.apply"}:
        if set(desired_state) != {"enabled", "activation"}:
            raise ValueError(f"Redfish {operation} requires enabled and activation")
        if not isinstance(desired_state.get("enabled"), bool):
            raise ValueError(f"Redfish {operation} enabled must be boolean")
        if str(desired_state.get("activation") or "").lower() not in REDFISH_PLATFORM_ACTIVATIONS:
            raise ValueError(f"Redfish {operation} activation must be immediate or reboot")
        return
    if operation == "boot-order.apply":
        if set(desired_state) != {"order", "activation"}:
            raise ValueError("Redfish boot-order.apply requires order and activation")
        order = desired_state.get("order")
        if not isinstance(order, list) or not 1 <= len(order) <= 32:
            raise ValueError("Redfish boot order must contain between 1 and 32 exact boot option references")
        normalized = [str(item or "") for item in order]
        if any(not REDFISH_BOOT_ORDER_REF_RE.fullmatch(item) for item in normalized):
            raise ValueError("Redfish boot order contains an unsafe boot option reference")
        if len(set(normalized)) != len(normalized):
            raise ValueError("Redfish boot order references must be unique")
        if str(desired_state.get("activation") or "").lower() not in REDFISH_PLATFORM_ACTIVATIONS:
            raise ValueError("Redfish boot order activation must be immediate or reboot")
        return
    if operation == "bios.apply":
        if set(desired_state) != {"attributes"}:
            raise ValueError("Redfish bios.apply requires only desired_state.attributes")
        attributes = desired_state.get("attributes")
        if not isinstance(attributes, dict) or not attributes or len(attributes) > 64:
            raise ValueError("Redfish bios.apply attributes must contain between 1 and 64 entries")
        for raw_name, raw_value in attributes.items():
            name = str(raw_name)
            if not REDFISH_BIOS_ATTRIBUTE_RE.fullmatch(name):
                raise ValueError("Redfish BIOS attribute name is unsafe")
            if isinstance(raw_value, bool):
                continue
            if isinstance(raw_value, int) and not isinstance(raw_value, bool):
                if raw_value < -(2**63) or raw_value > 2**63 - 1:
                    raise ValueError("Redfish BIOS integer attribute is out of range")
                continue
            if isinstance(raw_value, str) and raw_value and len(raw_value) <= 256 and not any(ord(ch) < 32 for ch in raw_value):
                continue
            raise ValueError("Redfish BIOS attribute values must be bounded string, integer or boolean scalars")
        return
    if operation == "firmware.apply":
        if set(desired_state) != {"image_url", "component_id", "expected_version"}:
            raise ValueError("Redfish firmware.apply requires only image_url, component_id and expected_version")
        image_url = str(desired_state.get("image_url") or "")
        parsed = urlparse(image_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise ValueError("Redfish firmware image_url must be credential-free HTTPS without query/fragment")
        component_id = str(desired_state.get("component_id") or "")
        if not REDFISH_FIRMWARE_COMPONENT_RE.fullmatch(component_id):
            raise ValueError("Redfish firmware component_id is unsafe")
        expected_version = str(desired_state.get("expected_version") or "")
        if not expected_version or len(expected_version) > 160 or any(ord(ch) < 32 for ch in expected_version):
            raise ValueError("Redfish firmware expected_version must be a bounded printable string")
        return
    if operation == "storage.volume.apply":
        if set(desired_state) != {"controller_id", "volume_name", "raid_type", "drive_ids"}:
            raise ValueError("Redfish storage.volume.apply requires only controller_id, volume_name, raid_type and drive_ids")
        controller_id = str(desired_state.get("controller_id") or "")
        volume_name = str(desired_state.get("volume_name") or "")
        raid_type = str(desired_state.get("raid_type") or "").upper()
        drive_ids = desired_state.get("drive_ids")
        if not REDFISH_STORAGE_ID_RE.fullmatch(controller_id):
            raise ValueError("Redfish storage controller_id is unsafe")
        if not REDFISH_VOLUME_NAME_RE.fullmatch(volume_name):
            raise ValueError("Redfish storage volume_name is unsafe")
        if raid_type not in REDFISH_RAID_TYPES:
            raise ValueError("unsupported Redfish RAID type")
        if not isinstance(drive_ids, list) or not 1 <= len(drive_ids) <= 64:
            raise ValueError("Redfish storage drive_ids must contain between 1 and 64 exact drive IDs")
        normalized = [str(item or "") for item in drive_ids]
        if any(not REDFISH_STORAGE_ID_RE.fullmatch(item) for item in normalized):
            raise ValueError("Redfish storage drive_id is unsafe")
        if len(set(normalized)) != len(normalized):
            raise ValueError("Redfish storage drive_ids must be unique")
        minimum = {"RAID0": 1, "RAID1": 2, "RAID5": 3, "RAID6": 4, "RAID10": 4, "RAID50": 6, "RAID60": 8}[raid_type]
        if len(normalized) < minimum:
            raise ValueError(f"{raid_type} requires at least {minimum} drives")
        return
    if operation == "storage.volume.delete":
        if set(desired_state) != {"controller_id", "volume_id", "confirm_volume_id"}:
            raise ValueError("Redfish storage.volume.delete requires controller_id, volume_id and confirm_volume_id")
        controller_id = str(desired_state.get("controller_id") or "")
        volume_id = str(desired_state.get("volume_id") or "")
        confirm = str(desired_state.get("confirm_volume_id") or "")
        if not REDFISH_STORAGE_ID_RE.fullmatch(controller_id) or not REDFISH_STORAGE_ID_RE.fullmatch(volume_id):
            raise ValueError("Redfish storage controller/volume ID is unsafe")
        if confirm != volume_id:
            raise ValueError("Redfish storage volume deletion confirmation must exactly match volume_id")
        return
    allowed = {"target", "enabled", "mode"}
    unknown = sorted(set(desired_state) - allowed)
    if unknown:
        raise ValueError("unsupported Redfish boot desired_state field(s): " + ", ".join(unknown))
    if str(desired_state.get("target") or "").lower() not in REDFISH_BOOT_TARGETS:
        raise ValueError("unsupported Redfish boot target")
    if str(desired_state.get("enabled") or "once").lower() not in REDFISH_BOOT_ENABLED:
        raise ValueError("unsupported Redfish boot enable mode")
    mode = str(desired_state.get("mode") or "").lower()
    if mode and mode not in REDFISH_BOOT_MODES:
        raise ValueError("unsupported Redfish boot mode")


def validate_network_switch_provider(provider: dict[str, Any], desired_state: dict[str, Any] | None = None, operation: str | None = None) -> None:
    endpoint = str(provider.get("endpoint") or "")
    parsed = urlparse(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise ValueError("network-switch endpoint must be credential-free HTTPS")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise ValueError("network-switch endpoint must use an IP literal, not a hostname") from exc
    if parsed.path.rstrip("/") != "/restconf/data":
        raise ValueError("network-switch endpoint must use the fixed /restconf/data root")
    if str(provider.get("api_version") or "") != SWITCH_RESTCONF_API_VERSION:
        raise ValueError("network-switch api_version does not match the supported RESTCONF profile")
    if str(provider.get("implementation_version") or "") != SWITCH_RESTCONF_IMPLEMENTATION_VERSION:
        raise ValueError("network-switch implementation_version does not match the supported RESTCONF profile")
    capabilities = provider.get("capabilities") if isinstance(provider.get("capabilities"), dict) else {}
    if set(capabilities) - {"profile", "model", "port_allowlist", "vlan_allowlist", "port_modes"}:
        raise ValueError("network-switch capabilities contain unsupported fields")
    if capabilities.get("profile") != SWITCH_RESTCONF_PROFILE:
        raise ValueError("network-switch requires the supported pinned RESTCONF profile")
    model = str(capabilities.get("model") or "")
    if not SWITCH_VLAN_NAME_RE.fullmatch(model):
        raise ValueError("network-switch model pin is invalid")
    ports = capabilities.get("port_allowlist")
    vlans = capabilities.get("vlan_allowlist")
    if not isinstance(ports, list) or not 1 <= len(ports) <= 128:
        raise ValueError("network-switch requires a bounded non-empty port_allowlist")
    if not isinstance(vlans, list) or not 1 <= len(vlans) <= 256:
        raise ValueError("network-switch requires a bounded non-empty vlan_allowlist")
    normalized_ports = [str(item) for item in ports]
    normalized_vlans = list(vlans)
    if any(not SWITCH_PORT_RE.fullmatch(item) for item in normalized_ports) or len(set(normalized_ports)) != len(normalized_ports):
        raise ValueError("network-switch port_allowlist contains unsafe or duplicate entries")
    if any(not isinstance(item, int) or isinstance(item, bool) or not 1 <= item <= 4094 for item in normalized_vlans) or len(set(normalized_vlans)) != len(normalized_vlans):
        raise ValueError("network-switch vlan_allowlist contains invalid or duplicate VLAN IDs")
    mode_policy = capabilities.get("port_modes", {})
    if not isinstance(mode_policy, dict) or set(mode_policy) - set(normalized_ports):
        raise ValueError("network-switch port_modes must only reference allowlisted ports")
    for port, modes in mode_policy.items():
        if not isinstance(modes, list) or not modes or len(modes) > 2 or set(modes) - {"access", "trunk"}:
            raise ValueError("network-switch port_modes must contain access and/or trunk")
    if desired_state is None or operation is None:
        return
    if operation == "vlan.ensure" and desired_state["vlan_id"] not in set(normalized_vlans):
        raise ValueError("network-switch VLAN is not allowlisted by provider capabilities")
    if operation == "port.configure":
        port = desired_state["port"]
        if port not in set(normalized_ports):
            raise ValueError("network-switch port is not allowlisted by provider capabilities")
        mode = desired_state["mode"]
        if mode_policy.get(port) and mode not in set(mode_policy[port]):
            raise ValueError("network-switch port mode is not permitted by provider capabilities")
        vlan_ids = [desired_state["access_vlan"]] if mode == "access" else desired_state["trunk_vlans"]
        denied = sorted(set(vlan_ids) - set(normalized_vlans))
        if denied:
            raise ValueError("network-switch VLAN is not allowlisted by provider capabilities: " + ", ".join(str(item) for item in denied))


def validate_proxmox_vm_provider(provider: dict[str, Any], desired_state: dict[str, Any] | None = None, operation: str | None = None) -> None:
    endpoint = str(provider.get("endpoint") or "")
    parsed = urlparse(endpoint)
    if (
        parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None
        or parsed.query or parsed.fragment or parsed.port != 8006 or parsed.path.rstrip("/") != "/api2/json"
    ):
        raise ValueError("Proxmox VM runtime endpoint must be credential-free HTTPS on port 8006 with /api2/json root")
    if (str(provider.get("api_version") or ""), str(provider.get("implementation_version") or "")) != (PROXMOX_VM_API_VERSION, PROXMOX_VM_IMPLEMENTATION_VERSION):
        raise ValueError("Proxmox provider versions do not match the supported VM runtime profile")
    caps = provider.get("capabilities") if isinstance(provider.get("capabilities"), dict) else {}
    allowed = {"profile", "node_allowlist", "storage_allowlist", "bridge_allowlist", "template_allowlist", "vm_id_min", "vm_id_max", "max_cpu_cores", "max_memory_mib", "max_disk_gib", "max_nics", "max_snapshots", "action_allowlist", "allow_vm_delete", "allow_snapshot_restore"}
    if set(caps) - allowed or caps.get("profile") != PROXMOX_VM_IMPLEMENTATION_VERSION:
        raise ValueError("Proxmox VM runtime capabilities do not match the pinned profile")
    def ids(field: str, *, required: bool) -> set[str]:
        values = caps.get(field)
        if not isinstance(values, list) or (required and not values) or len(values) > 128:
            raise ValueError(f"Proxmox {field} must be a bounded allowlist")
        normalized = [str(item) for item in values]
        if len(set(normalized)) != len(normalized) or any(not PROXMOX_ID_RE.fullmatch(item) for item in normalized):
            raise ValueError(f"Proxmox {field} contains unsafe or duplicate entries")
        return set(normalized)
    nodes = ids("node_allowlist", required=True)
    storage = ids("storage_allowlist", required=True)
    bridges = ids("bridge_allowlist", required=False)
    actions = caps.get("action_allowlist")
    if not isinstance(actions, list) or not actions or len(actions) > len(PROXMOX_VM_OPERATIONS) or set(actions) - PROXMOX_VM_OPERATIONS or len(set(actions)) != len(actions):
        raise ValueError("Proxmox action_allowlist is invalid")
    low = _proxmox_integer(caps.get("vm_id_min"), field="vm_id_min", low=100, high=2_147_483_647)
    high = _proxmox_integer(caps.get("vm_id_max"), field="vm_id_max", low=low, high=2_147_483_647)
    for field in ("max_cpu_cores", "max_memory_mib", "max_disk_gib"):
        _proxmox_integer(caps.get(field), field=field, low=1, high=1_048_576)
    _proxmox_integer(caps.get("max_nics"), field="max_nics", low=1, high=8)
    _proxmox_integer(caps.get("max_snapshots"), field="max_snapshots", low=1, high=128)
    templates = caps.get("template_allowlist")
    if not isinstance(templates, list) or len(templates) > 128:
        raise ValueError("Proxmox template_allowlist must be bounded")
    template_ids: set[tuple[str, int]] = set()
    for item in templates:
        if not isinstance(item, dict) or set(item) != {"node", "vm_id"}:
            raise ValueError("Proxmox template_allowlist entries must contain only node and vm_id")
        node = _proxmox_identifier(item.get("node"), field="template node")
        vm_id = _proxmox_integer(item.get("vm_id"), field="template vm_id", low=100, high=2_147_483_647)
        template_ids.add((node, vm_id))
    if len(template_ids) != len(templates):
        raise ValueError("Proxmox template_allowlist must not contain duplicates")
    if not isinstance(caps.get("allow_vm_delete"), bool) or not isinstance(caps.get("allow_snapshot_restore"), bool):
        raise ValueError("Proxmox destructive capability flags must be boolean")
    if desired_state is None or operation is None:
        return
    if operation not in set(actions):
        raise ValueError("Proxmox operation is disabled by provider action_allowlist")
    for field in ("node", "source_node", "target_node"):
        if field in desired_state and desired_state[field] not in nodes:
            raise ValueError("Proxmox node is not allowlisted by provider capabilities")
    if "storage" in desired_state and desired_state["storage"] not in storage:
        raise ValueError("Proxmox storage is not allowlisted by provider capabilities")
    if "bridge" in desired_state and desired_state["bridge"] not in bridges:
        raise ValueError("Proxmox bridge is not allowlisted by provider capabilities")
    for field in ("vm_id", "target_vm_id"):
        if field in desired_state and not low <= desired_state[field] <= high:
            raise ValueError("Proxmox VM ID is outside the provider policy range")
    if operation == "vm.clone" and (desired_state["source_node"], desired_state["source_vm_id"]) not in template_ids:
        raise ValueError("Proxmox clone source is not an allowlisted template")
    if operation == "vm.delete" and caps["allow_vm_delete"] is not True:
        raise ValueError("Proxmox VM deletion is disabled by provider capabilities")
    if operation == "snapshot.restore" and caps["allow_snapshot_restore"] is not True:
        raise ValueError("Proxmox snapshot restore is disabled by provider capabilities")
    for field, limit in (("cpu_cores", "max_cpu_cores"), ("memory_mib", "max_memory_mib"), ("disk_gib", "max_disk_gib")):
        if field in desired_state and desired_state[field] > caps[limit]:
            raise ValueError(f"Proxmox {field} exceeds the provider policy limit")


def infrastructure_runtime_capable(plan: dict[str, Any]) -> bool:
    provider = plan.get("provider") if isinstance(plan.get("provider"), dict) else {}
    preview = plan.get("runtime_preview") if isinstance(plan.get("runtime_preview"), dict) else {}
    kind = str(provider.get("kind") or "")
    operation = str(plan.get("operation") or "")
    return (
        infrastructure_runtime_operation_capable(kind, operation)
        and preview.get("provider_kind") == kind
        and preview.get("operation") == operation
        and preview.get("active_probe") is True
        and preview.get("secret_output_suppressed") is True
        and preview.get("credential_material_returned") is False
        and preview.get("arbitrary_cli") is False
        and preview.get("arbitrary_shell") is False
        and isinstance(preview.get("current_hash"), str)
        and len(preview["current_hash"]) == 64
    )


def infrastructure_plan(
    *,
    provider: dict[str, Any],
    provider_snapshot: dict[str, Any],
    operation: str,
    subject_targets: list[dict[str, Any]],
    desired_state: dict[str, Any],
    runtime_preview: dict[str, Any] | None = None,
    artifact_supply: dict[str, Any] | None = None,
) -> dict[str, Any]:
    provider_kind = provider["kind"]
    if provider_kind in CLOUD_PROVIDER_CONTRACTS:
        contract = CLOUD_PROVIDER_CONTRACTS[provider_kind]
        kind = contract["plan_contract"]
        stages = ["validate-provider", "discover-current", "render-diff", "apply", "verify"]
    elif provider_kind in BARE_METAL_PROVIDER_CONTRACTS:
        contract = BARE_METAL_PROVIDER_CONTRACTS[provider_kind]
        kind = contract["plan_contract"]
        stages = ["validate-provider", "discover-hardware", "render-diff", "apply", "post-install-verify"]
    elif provider_kind in NETWORK_PROVIDER_CONTRACTS:
        contract = NETWORK_PROVIDER_CONTRACTS[provider_kind]
        kind = contract["plan_contract"]
        stages = ["validate-provider", "discover-network", "render-diff", "apply", "connectivity-verify"]
    else:
        raise ValueError(f"unsupported infrastructure provider kind: {provider_kind}")
    if operation not in contract["actions"]:
        raise ValueError(f"operation {operation} is not supported by {provider_kind}")
    validate_infrastructure_desired_state(provider_kind, operation, desired_state)
    if provider_kind == "network-switch":
        validate_network_switch_provider(provider, desired_state, operation)
    if provider_kind == "proxmox":
        validate_proxmox_vm_provider(provider, desired_state, operation)
    runtime_operation = infrastructure_runtime_operation_capable(provider_kind, operation)
    if runtime_preview is not None:
        if not runtime_operation:
            raise ValueError(f"runtime preview is not supported for {provider_kind} {operation}")
        if runtime_preview.get("provider_kind") != provider_kind or runtime_preview.get("operation") != operation:
            raise ValueError("infrastructure runtime preview does not match provider operation")
        if runtime_preview.get("secret_output_suppressed") is not True or runtime_preview.get("credential_material_returned") is not False:
            raise ValueError("infrastructure runtime preview violates credential boundary")
        if runtime_preview.get("arbitrary_cli") is not False or runtime_preview.get("arbitrary_shell") is not False:
            raise ValueError("infrastructure runtime preview exposes an arbitrary command surface")
    if provider_kind == "redfish" and operation == "secure-boot.apply":
        capabilities = provider.get("capabilities") if isinstance(provider.get("capabilities"), dict) else {}
        policy = capabilities.get("secure_boot")
        if not isinstance(policy, dict) or set(policy) - {"activation", "reset_type"}:
            raise ValueError("Redfish secure boot requires a bounded capabilities.secure_boot policy")
        activation = str(policy.get("activation") or "").lower()
        if activation != "reboot":
            raise ValueError("Redfish secure boot capability activation must be reboot")
        if str(desired_state.get("activation") or "").lower() != activation:
            raise ValueError("Redfish secure boot desired activation does not match provider capability")
        if str(policy.get("reset_type") or "") not in REDFISH_RESET_TYPES:
            raise ValueError("Redfish secure boot requires a fixed supported reset_type")
    if provider_kind == "redfish" and operation in {"sriov.apply", "iommu.apply"}:
        capabilities = provider.get("capabilities") if isinstance(provider.get("capabilities"), dict) else {}
        feature = operation.split(".", 1)[0]
        feature_map = capabilities.get("hardware_feature_map")
        if not isinstance(feature_map, dict):
            raise ValueError("Redfish platform feature runtime requires capabilities.hardware_feature_map")
        policy = feature_map.get(feature)
        allowed_keys = {"attribute", "enabled_value", "disabled_value", "activation", "reset_type"}
        if not isinstance(policy, dict) or set(policy) - allowed_keys:
            raise ValueError(f"Redfish {feature} capability mapping is missing or contains unsupported fields")
        attribute = str(policy.get("attribute") or "")
        if not REDFISH_BIOS_ATTRIBUTE_RE.fullmatch(attribute):
            raise ValueError(f"Redfish {feature} capability attribute is unsafe")
        raw_allowlist = capabilities.get("bios_attribute_allowlist")
        if not isinstance(raw_allowlist, list) or attribute not in {str(item) for item in raw_allowlist}:
            raise ValueError(f"Redfish {feature} capability attribute must also be BIOS-allowlisted")
        for key in ("enabled_value", "disabled_value"):
            value = policy.get(key)
            if not isinstance(value, (str, int, bool)) or (isinstance(value, str) and (not value or len(value) > 256 or any(ord(ch) < 32 for ch in value))):
                raise ValueError(f"Redfish {feature} capability {key} must be a bounded scalar")
        if policy.get("enabled_value") == policy.get("disabled_value"):
            raise ValueError(f"Redfish {feature} enabled and disabled capability values must differ")
        activation = str(policy.get("activation") or "").lower()
        if activation not in REDFISH_PLATFORM_ACTIVATIONS:
            raise ValueError(f"Redfish {feature} capability activation must be immediate or reboot")
        if str(desired_state.get("activation") or "").lower() != activation:
            raise ValueError(f"Redfish {feature} desired activation does not match provider capability")
        if activation == "reboot" and str(policy.get("reset_type") or "") not in REDFISH_RESET_TYPES:
            raise ValueError(f"Redfish {feature} reboot activation requires a fixed supported reset_type")
        if activation == "immediate" and policy.get("reset_type") not in {None, ""}:
            raise ValueError(f"Redfish {feature} immediate activation must not configure reset_type")
    if provider_kind == "redfish" and operation == "boot-order.apply":
        capabilities = provider.get("capabilities") if isinstance(provider.get("capabilities"), dict) else {}
        policy = capabilities.get("boot_order")
        allowed_keys = {"allowlist", "activation", "reset_type"}
        if not isinstance(policy, dict) or set(policy) - allowed_keys:
            raise ValueError("Redfish boot-order runtime requires a bounded capabilities.boot_order policy")
        raw_order = policy.get("allowlist")
        if not isinstance(raw_order, list) or not raw_order or len(raw_order) > 64:
            raise ValueError("Redfish boot-order runtime requires a non-empty exact allowlist")
        allowed = [str(item) for item in raw_order]
        if any(not REDFISH_BOOT_ORDER_REF_RE.fullmatch(item) for item in allowed) or len(set(allowed)) != len(allowed):
            raise ValueError("Redfish boot-order allowlist contains unsafe or duplicate references")
        denied = [item for item in desired_state.get("order") or [] if str(item) not in set(allowed)]
        if denied:
            raise ValueError("Redfish boot option is not allowlisted by provider capabilities: " + ", ".join(str(item) for item in denied))
        activation = str(policy.get("activation") or "").lower()
        if activation not in REDFISH_PLATFORM_ACTIVATIONS:
            raise ValueError("Redfish boot-order capability activation must be immediate or reboot")
        if str(desired_state.get("activation") or "").lower() != activation:
            raise ValueError("Redfish boot-order desired activation does not match provider capability")
        if activation == "reboot" and str(policy.get("reset_type") or "") not in REDFISH_RESET_TYPES:
            raise ValueError("Redfish boot-order reboot activation requires a fixed supported reset_type")
        if activation == "immediate" and policy.get("reset_type") not in {None, ""}:
            raise ValueError("Redfish boot-order immediate activation must not configure reset_type")
    if provider_kind == "redfish" and operation.startswith("storage.volume."):
        capabilities = provider.get("capabilities") if isinstance(provider.get("capabilities"), dict) else {}
        raw_controllers = capabilities.get("storage_controller_allowlist")
        if not isinstance(raw_controllers, dict) or not raw_controllers:
            raise ValueError("Redfish storage runtime requires capabilities.storage_controller_allowlist")
        controller_id = str(desired_state.get("controller_id") or "")
        controller_policy = raw_controllers.get(controller_id)
        if not isinstance(controller_policy, dict):
            raise ValueError("Redfish storage controller is not allowlisted by provider capabilities")
        allowed_keys = {"drive_ids", "raid_types", "volume_names", "allow_volume_delete"}
        if set(controller_policy) - allowed_keys:
            raise ValueError("Redfish storage controller allowlist contains unsupported policy fields")
        if operation == "storage.volume.apply":
            raw_drives = controller_policy.get("drive_ids")
            raw_raid = controller_policy.get("raid_types")
            raw_names = controller_policy.get("volume_names")
            if not isinstance(raw_drives, list) or not raw_drives or not isinstance(raw_raid, list) or not raw_raid or not isinstance(raw_names, list) or not raw_names:
                raise ValueError("Redfish storage apply requires drive_ids, raid_types and volume_names allowlists")
            denied_drives = sorted(set(str(item) for item in desired_state.get("drive_ids") or []) - set(str(item) for item in raw_drives))
            if denied_drives:
                raise ValueError("Redfish storage drive is not allowlisted: " + ", ".join(denied_drives))
            if str(desired_state.get("raid_type") or "").upper() not in {str(item).upper() for item in raw_raid}:
                raise ValueError("Redfish RAID type is not allowlisted by provider capabilities")
            if str(desired_state.get("volume_name") or "") not in {str(item) for item in raw_names}:
                raise ValueError("Redfish storage volume name is not allowlisted by provider capabilities")
        elif controller_policy.get("allow_volume_delete") is not True:
            raise ValueError("Redfish storage volume deletion is disabled by provider capabilities")
    if provider_kind == "pxe":
        capabilities = provider.get("capabilities") if isinstance(provider.get("capabilities"), dict) else {}
        if capabilities.get("network_scope") != "private-offline":
            raise ValueError("PXE runtime requires provider capabilities.network_scope=private-offline")
        if capabilities.get("artifact_delivery") != "shared-readonly-mirror":
            raise ValueError("PXE runtime requires provider capabilities.artifact_delivery=shared-readonly-mirror")
        if not isinstance(artifact_supply, dict) or artifact_supply.get("mode") != "pxe-ready-manifest-bound":
            raise ValueError("PXE runtime requires an exact READY artifact supply")
        if artifact_supply.get("credential_material_in_plan") is not False or artifact_supply.get("public_network_required") is not False:
            raise ValueError("PXE artifact supply violates credential/network boundary")
        if not isinstance(artifact_supply.get("manifest_hash"), str) or len(artifact_supply["manifest_hash"]) != 64:
            raise ValueError("PXE artifact supply manifest hash is invalid")
    elif artifact_supply is not None:
        raise ValueError("artifact_supply is only supported for trusted PXE infrastructure runtime")
    plan = {
        "schema_version": 5,
        "kind": kind,
        "operation": operation,
        "provider": {
            "id": provider["id"],
            "kind": provider_kind,
            "api_version": provider["api_version"],
            "implementation_version": provider["implementation_version"],
            "credential_ref": provider["credential_ref"],
            "snapshot_hash": provider_snapshot["snapshot_hash"],
        },
        "targets": [provider_snapshot, *subject_targets],
        "desired_state": desired_state,
        "runtime_preview": runtime_preview,
        "runtime": {
            "state": "RUNTIME_CAPABLE" if runtime_operation and runtime_preview is not None else ("PREVIEW_REQUIRED" if runtime_operation else "CONTRACT_ONLY"),
            "executor": "infrastructure-provider-worker" if runtime_operation else "infrastructure-provider-contract",
            "active_verification": runtime_operation,
        },
        "stages": stages,
        "credential_delivery": "credential-service-to-provider-worker-only",
        "credential_material_in_plan": False,
        "verification_required": True,
        "mutation_gate": MUTATION_GATE,
        "arbitrary_cli_or_shell": False,
    }
    if artifact_supply is not None:
        plan["artifact_supply"] = artifact_supply
    return _finish(plan)


ARTIFACT_RUNTIME_SOURCE_SCHEMES = {"file", "https", "oci"}
ARTIFACT_RUNTIME_DESTINATION_SCHEMES = {"file", "oci"}


def validate_artifact_mirror_parameters(parameters: dict[str, Any]) -> None:
    allowed = {"verify_destination", "replace_existing"}
    unknown = sorted(set(parameters) - allowed)
    if unknown:
        raise ValueError(f"unsupported artifact mirror parameter(s): {', '.join(unknown)}")
    if parameters.get("verify_destination", True) is not True:
        raise ValueError("artifact mirror destination digest verification cannot be disabled")
    if "replace_existing" in parameters and not isinstance(parameters["replace_existing"], bool):
        raise ValueError("replace_existing must be boolean")


def artifact_mirror_runtime_capable(plan: dict[str, Any]) -> bool:
    artifact = plan.get("artifact") if isinstance(plan.get("artifact"), dict) else {}
    source_scheme = urlparse(str(artifact.get("source") or "")).scheme.lower()
    destination_scheme = urlparse(str(artifact.get("destination") or "")).scheme.lower()
    git_release_runtime = artifact.get("kind") == "git-release" and source_scheme == "https" and destination_scheme == "file"
    ansible_collection_runtime = artifact.get("kind") == "ansible-collection" and source_scheme in {"file", "https"} and destination_scheme == "file"
    repository_runtime = artifact.get("kind") in {"apt-repository", "rpm-repository", "python-repository"} and source_scheme in {"file", "https"} and destination_scheme == "file"
    blob_runtime = source_scheme in {"file", "https"} and destination_scheme == "file" and not git_release_runtime and not ansible_collection_runtime and not repository_runtime
    oci_runtime = artifact.get("kind") in {"oci-image", "helm-chart"} and source_scheme == "oci" and destination_scheme == "oci"
    return plan.get("operation") == "artifact.mirror.apply" and (blob_runtime or oci_runtime or git_release_runtime or ansible_collection_runtime or repository_runtime)


def artifact_mirror_plan(*, artifact_snapshot: dict[str, Any], parameters: dict[str, Any]) -> dict[str, Any]:
    validate_artifact_mirror_parameters(parameters)
    source_scheme = urlparse(str(artifact_snapshot["source"])).scheme.lower()
    destination_scheme = urlparse(str(artifact_snapshot["destination"])).scheme.lower()
    git_release_runtime = artifact_snapshot.get("kind") == "git-release" and source_scheme == "https" and destination_scheme == "file"
    ansible_collection_runtime = artifact_snapshot.get("kind") == "ansible-collection" and source_scheme in {"file", "https"} and destination_scheme == "file"
    repository_runtime = artifact_snapshot.get("kind") in {"apt-repository", "rpm-repository", "python-repository"} and source_scheme in {"file", "https"} and destination_scheme == "file"
    blob_runtime = source_scheme in {"file", "https"} and destination_scheme == "file" and not git_release_runtime and not ansible_collection_runtime and not repository_runtime
    oci_runtime = artifact_snapshot.get("kind") in {"oci-image", "helm-chart"} and source_scheme == "oci" and destination_scheme == "oci"
    runtime_capable = blob_runtime or git_release_runtime or ansible_collection_runtime or repository_runtime or oci_runtime
    return _finish({
        "schema_version": 4,
        "kind": "ArtifactMirrorPlan",
        "operation": "artifact.mirror.apply",
        "targets": [artifact_snapshot],
        "artifact": {
            "id": artifact_snapshot["id"],
            "kind": artifact_snapshot["kind"],
            "source": artifact_snapshot["source"],
            "destination": artifact_snapshot["destination"],
            "version": artifact_snapshot["version"],
            "digest": artifact_snapshot["digest"],
            "labels": (
                {key: artifact_snapshot.get("labels", {}).get(key) for key in ("git_ref", "git_commit") if artifact_snapshot.get("labels", {}).get(key) is not None}
                if artifact_snapshot.get("kind") == "git-release"
                else (
                    {key: artifact_snapshot.get("labels", {}).get(key) for key in ("ansible_namespace", "ansible_name") if artifact_snapshot.get("labels", {}).get(key) is not None}
                    if artifact_snapshot.get("kind") == "ansible-collection"
                    else (
                        {key: artifact_snapshot.get("labels", {}).get(key) for key in ("repository_id", "apt_distribution", "apt_components", "apt_architectures", "signature_policy") if artifact_snapshot.get("labels", {}).get(key) is not None}
                        if artifact_snapshot.get("kind") in {"apt-repository", "rpm-repository", "python-repository"}
                        else {}
                    )
                )
            ),
        },
        "parameters": {"verify_destination": True, "replace_existing": bool(parameters.get("replace_existing", False))},
        "runtime": {
            "state": "RUNTIME_CAPABLE" if runtime_capable else "CONTRACT_ONLY",
            "mode": (
                "git-release-exact-tag-archive" if git_release_runtime else
                "ansible-collection-archive" if ansible_collection_runtime else
                f"{artifact_snapshot.get('kind')}-snapshot" if repository_runtime else
                "oci-registry" if source_scheme == "oci" else
                "digest-pinned-blob"
            ),
            "executor": "artifact-mirror-worker" if runtime_capable else "artifact-mirror-contract",
            "source_scheme": source_scheme,
            "destination_scheme": destination_scheme,
            "supported_source_schemes": sorted(ARTIFACT_RUNTIME_SOURCE_SCHEMES),
            "supported_destination_schemes": sorted(ARTIFACT_RUNTIME_DESTINATION_SCHEMES),
        },
        "stages": (
            ["resolve-source", "fetch-snapshot", "verify-source-digest", "verify-native-repository-metadata", "atomic-publish", "verify-destination-tree", "record-audit"]
            if repository_runtime
            else ["resolve-source", "fetch", "verify-source-digest", "mirror", "verify-destination-digest", "record-audit"]
        ),
        "digest_verification_required": True,
        "mutation_gate": MUTATION_GATE,
    })


def contracts() -> dict[str, Any]:
    return {
        "schema_version": 4,
        "channels": ["ui", "telegram", "hermes-bot", "api"],
        "shared_intent_backend": True,
        "read_operations": READ_OPERATIONS,
        "day2_operations": DAY2_OPERATIONS,
        "kubernetes_day2_runtime": KUBERNETES_DAY2_RUNTIME_OPERATIONS,
        "cluster_provider_day2_runtime": PROVIDER_DAY2_RUNTIME_OPERATIONS,
        "cloud_virtualization": CLOUD_PROVIDER_CONTRACTS,
        "bare_metal": BARE_METAL_PROVIDER_CONTRACTS,
        "network": NETWORK_PROVIDER_CONTRACTS,
        "infrastructure_runtime": {key: sorted(value) for key, value in INFRASTRUCTURE_RUNTIME_OPERATIONS.items()},
        "artifact_kinds": list(ARTIFACT_KINDS),
        "verification_checks": VERIFICATION_CHECKS,
        "credential_boundary": "raw-credentials-never-enter-llm-ui-telegram-plans",
        "mutation_invariant": "intent -> typed plan -> ChangeSet -> deterministic preview/diff -> risk -> policy -> approval -> exact-hash binding -> constrained execution ticket -> broker/provider/agent -> verification -> audit",
    }
