from __future__ import annotations

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
        "actions": ["power.set", "boot.set", "bios.apply", "firmware.apply", "inventory.refresh"],
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
}

NETWORK_PROVIDER_CONTRACTS: dict[str, dict[str, Any]] = {
    "network-switch": {
        "kind": "network-infrastructure",
        "plan_contract": "SwitchNetworkPlan",
        "credential_boundary": "credential-service-provider-worker-only",
        "actions": ["vlan.ensure", "port.configure", "bond.ensure", "network.attach", "network.detach"],
        "arbitrary_cli": False,
    }
}

ARTIFACT_KINDS = ("oci-image", "helm-chart", "package", "git-release")

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
    "cluster.etcd.snapshot": {"kind": "EtcdSnapshotPlan", "stages": ["preflight", "snapshot", "integrity-verify"]},
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
}

KUBERNETES_DAY2_RUNTIME_OPERATIONS: dict[str, dict[str, Any]] = {
    "cluster.node.cordon": {"executor": "kubernetes-broker", "verification": ["node-unschedulable"]},
    "cluster.node.uncordon": {"executor": "kubernetes-broker", "verification": ["node-schedulable"]},
    "cluster.node.drain": {"executor": "kubernetes-broker", "verification": ["node-unschedulable", "drain-complete"]},
    "cluster.workload.restart": {"executor": "kubernetes-broker", "verification": ["rollout-complete"]},
    "cluster.workload.scale": {"executor": "kubernetes-broker", "verification": ["replicas-converged", "rollout-complete"]},
    "cluster.addon.install": {"executor": "kubernetes-broker", "verification": ["helm-release-ready"]},
    "cluster.addon.upgrade": {"executor": "kubernetes-broker", "verification": ["helm-release-ready"]},
    "cluster.helm.apply": {"executor": "kubernetes-broker", "verification": ["helm-release-ready"]},
}


def kubernetes_day2_runtime_capable(operation: str) -> bool:
    return operation in KUBERNETES_DAY2_RUNTIME_OPERATIONS


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
    else:
        for key in ("release", "chart", "namespace", "version"):
            if not str(parameters.get(key) or ""):
                raise ValueError(f"{key} is required for Helm-backed day-2 operations")
        if str(parameters.get("version")) in {"latest", "*"}:
            raise ValueError("Helm-backed day-2 operations require an explicit pinned version")
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


def day2_plan(*, operation: str, targets: list[dict[str, Any]], parameters: dict[str, Any], runtime_preview: dict[str, Any] | None = None) -> dict[str, Any]:
    contract = DAY2_OPERATIONS.get(operation)
    if not contract:
        raise ValueError(f"unsupported day-2 operation: {operation}")
    return _finish({
        "schema_version": 4,
        "kind": contract["kind"],
        "operation": operation,
        "targets": targets,
        "parameters": parameters,
        "runtime_preview": runtime_preview,
        "stages": contract["stages"],
        "verification_required": True,
        "mutation_gate": MUTATION_GATE,
        "arbitrary_shell": False,
    })


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


def infrastructure_plan(
    *,
    provider: dict[str, Any],
    provider_snapshot: dict[str, Any],
    operation: str,
    subject_targets: list[dict[str, Any]],
    desired_state: dict[str, Any],
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
    return _finish({
        "schema_version": 4,
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
        "stages": stages,
        "credential_delivery": "credential-service-to-provider-worker-only",
        "credential_material_in_plan": False,
        "verification_required": True,
        "mutation_gate": MUTATION_GATE,
        "arbitrary_cli_or_shell": False,
    })


ARTIFACT_RUNTIME_SOURCE_SCHEMES = {"file", "https"}
ARTIFACT_RUNTIME_DESTINATION_SCHEMES = {"file"}


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
    return (
        plan.get("operation") == "artifact.mirror.apply"
        and urlparse(str(artifact.get("source") or "")).scheme.lower() in ARTIFACT_RUNTIME_SOURCE_SCHEMES
        and urlparse(str(artifact.get("destination") or "")).scheme.lower() in ARTIFACT_RUNTIME_DESTINATION_SCHEMES
    )


def artifact_mirror_plan(*, artifact_snapshot: dict[str, Any], parameters: dict[str, Any]) -> dict[str, Any]:
    validate_artifact_mirror_parameters(parameters)
    source_scheme = urlparse(str(artifact_snapshot["source"])).scheme.lower()
    destination_scheme = urlparse(str(artifact_snapshot["destination"])).scheme.lower()
    runtime_capable = source_scheme in ARTIFACT_RUNTIME_SOURCE_SCHEMES and destination_scheme in ARTIFACT_RUNTIME_DESTINATION_SCHEMES
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
        },
        "parameters": {"verify_destination": True, "replace_existing": bool(parameters.get("replace_existing", False))},
        "runtime": {
            "state": "RUNTIME_CAPABLE" if runtime_capable else "CONTRACT_ONLY",
            "executor": "artifact-mirror-worker" if runtime_capable else "artifact-mirror-contract",
            "source_scheme": source_scheme,
            "destination_scheme": destination_scheme,
            "supported_source_schemes": sorted(ARTIFACT_RUNTIME_SOURCE_SCHEMES),
            "supported_destination_schemes": sorted(ARTIFACT_RUNTIME_DESTINATION_SCHEMES),
        },
        "stages": ["resolve-source", "fetch", "verify-source-digest", "mirror", "verify-destination-digest", "record-audit"],
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
        "cloud_virtualization": CLOUD_PROVIDER_CONTRACTS,
        "bare_metal": BARE_METAL_PROVIDER_CONTRACTS,
        "network": NETWORK_PROVIDER_CONTRACTS,
        "artifact_kinds": list(ARTIFACT_KINDS),
        "verification_checks": VERIFICATION_CHECKS,
        "credential_boundary": "raw-credentials-never-enter-llm-ui-telegram-plans",
        "mutation_invariant": "intent -> typed plan -> ChangeSet -> deterministic preview/diff -> risk -> policy -> approval -> exact-hash binding -> constrained execution ticket -> broker/provider/agent -> verification -> audit",
    }
