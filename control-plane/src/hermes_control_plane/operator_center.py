from __future__ import annotations

from typing import Any

UI_STATE = "IMPLEMENTED"


def _surface(
    surface_id: str,
    label: str,
    runtime_state: str,
    source: str,
    summary: str,
    *,
    action: str = "read",
) -> dict[str, Any]:
    return {
        "id": surface_id,
        "label": label,
        "ui_state": UI_STATE,
        "runtime_state": runtime_state,
        "source": source,
        "summary": summary,
        "action": action,
    }


GROUPS: list[dict[str, Any]] = [
    {
        "id": "kubernetes",
        "label": "Kubernetes",
        "surfaces": [
            _surface("kubernetes.overview", "Overview", "LIVE", "system/fleet/broker", "Cluster, broker and control-plane health."),
            _surface("kubernetes.issues", "Issues", "LIVE", "native diagnostics + optional Radar", "Executable native findings with optional Radar intelligence.", action="diagnostics"),
            _surface("kubernetes.applications", "Applications", "LIVE", "application registry + optional Radar", "Hermes application registry with optional provider intelligence."),
            _surface("kubernetes.topology", "Topology", "OPTIONAL_PROVIDER", "Radar get_topology / native inventory", "Topology is provider-backed when Radar is available; native inventory remains bounded."),
            _surface("kubernetes.network-live", "Network Live", "LIVE", "Cilium/Hubble via Kubernetes Broker", "Sanitized, namespace-authorized Hubble history and live collection.", action="network"),
            _surface("kubernetes.resources", "Resources", "OPTIONAL_PROVIDER", "Radar/list + Kubernetes discovery", "Authorized resource inventory without Secret bodies."),
            _surface("kubernetes.workloads", "Workloads", "LIVE", "native diagnostics + application registry", "Workload health and rollout diagnostics.", action="diagnostics"),
            _surface("kubernetes.nodes", "Nodes", "LIVE", "native diagnostics", "Node readiness and pressure checks.", action="diagnostics"),
            _surface("kubernetes.storage", "Storage", "LIVE", "native diagnostics", "PVC/storage health checks.", action="diagnostics"),
            _surface("kubernetes.ingress", "Ingress", "LIVE", "native diagnostics", "Ingress visibility and ingress TLS checks.", action="diagnostics"),
            _surface("kubernetes.metrics", "Metrics", "PARTIAL", "metrics.k8s.io diagnostics + optional Radar", "CPU/memory top-consumer summaries are live; full observability UX remains partial.", action="diagnostics"),
            _surface("kubernetes.logs", "Logs", "PARTIAL", "provider-dependent", "Dedicated workload-log runtime is not yet exposed through the Hermes read adapter."),
            _surface("kubernetes.timeline", "Timeline", "PARTIAL", "audit/events/provider-dependent", "Hermes audit and warning-event correlation are available; full change timeline remains partial."),
            _surface("kubernetes.helm", "Helm", "PARTIAL", "governed Kubernetes Broker", "Helm mutation runtime exists behind ChangeSets; dedicated read/history UI remains partial."),
            _surface("kubernetes.gitops", "GitOps", "PARTIAL", "Argo CD diagnostics + governed sync runtime", "Argo CD Application sync to an exact commit digest is executable; broader Argo/Flux runtime remains partial."),
            _surface("kubernetes.cost", "Cost", "CONTRACT_ONLY", "OpenCost add-on contract", "OpenCost is modeled but dedicated cost runtime/UI data is not complete."),
            _surface("kubernetes.tls", "TLS", "LIVE", "native diagnostics", "Ingress TLS and cert-manager compatibility findings.", action="diagnostics"),
            _surface("kubernetes.security", "Security", "LIVE", "native diagnostics", "Privileged/capability/hostPath/exposure/webhook baseline checks.", action="diagnostics"),
            _surface("kubernetes.rbac", "RBAC", "LIVE", "native diagnostics", "Dangerous Kubernetes RBAC permission checks.", action="diagnostics"),
            _surface("kubernetes.audit", "Audit", "LIVE", "Hermes audit", "Hermes governance and runtime audit trail."),
        ],
    },
    {
        "id": "cluster-factory",
        "label": "Cluster Factory",
        "surfaces": [
            _surface("cluster-factory.clusters", "Clusters", "LIVE", "cluster registry", "Cluster registry and state."),
            _surface("cluster-factory.servers", "Servers", "LIVE", "server registry", "Managed server inventory and preflight state."),
            _surface("cluster-factory.provision", "Provision", "PARTIAL", "ProvisioningRun + trusted cluster provider worker", "Bounded Kubespray/K3s/RKE2 offline provider execution is wired through signed exact-plan tickets; real-target repeatability and infrastructure-provider capacity creation remain open."),
            _surface("cluster-factory.templates", "Templates", "LIVE", "ClusterBlueprint/ClusterProfile", "Deterministic blueprint and profile definitions."),
            _surface("cluster-factory.bare-metal", "Bare Metal", "CONTRACT_ONLY", "Redfish/IPMI/PXE provider contracts", "UI surface exists; real bare-metal executors remain release-blocking."),
            _surface("cluster-factory.images-artifacts", "Images / Artifacts", "LIVE", "typed offline artifact supply + trusted mirrors", "Blob, OCI image, Helm OCI, exact-tag Git release, Ansible collection, APT, RPM and Python repository snapshot paths are executable and bind into exact READY provisioning manifests."),
        ],
    },
    {
        "id": "infrastructure",
        "label": "Infrastructure",
        "surfaces": [
            _surface("infrastructure.kubernetes", "Kubernetes", "LIVE", "Kubernetes Broker", "Trusted Kubernetes runtime and governed mutation boundary."),
            _surface("infrastructure.vmware", "VMware", "CONTRACT_ONLY", "typed provider contract", "Provider UI/contract exists; executor not yet runtime-complete."),
            _surface("infrastructure.openstack", "OpenStack", "CONTRACT_ONLY", "typed provider contract", "Provider UI/contract exists; executor not yet runtime-complete."),
            _surface("infrastructure.aws", "AWS", "CONTRACT_ONLY", "typed provider contract", "Provider UI/contract exists; executor not yet runtime-complete."),
            _surface("infrastructure.azure", "Azure", "CONTRACT_ONLY", "typed provider contract", "Provider UI/contract exists; executor not yet runtime-complete."),
            _surface("infrastructure.gcp", "GCP", "CONTRACT_ONLY", "typed provider contract", "Provider UI/contract exists; executor not yet runtime-complete."),
            _surface("infrastructure.docker", "Docker", "PARTIAL", "integration/agent capability contracts", "Metadata/capability surface exists; full operator runtime is partial."),
            _surface("infrastructure.swarm", "Swarm", "PARTIAL", "integration/agent capability contracts", "Metadata/capability surface exists; full operator runtime is partial."),
            _surface("infrastructure.ssh", "SSH", "PARTIAL", "server registry + preflight", "Server/preflight runtime exists; unrestricted SSH is intentionally forbidden."),
        ],
    },
    {
        "id": "operations",
        "label": "Operations",
        "surfaces": [
            _surface("operations.diagnostics", "Diagnostics", "LIVE", "native diagnostics + active unified verification", "Executable read-only diagnostic engine plus persisted active cluster verification.", action="diagnostics"),
            _surface("operations.deployments", "Deployments", "PARTIAL", "ChangeSets + operation jobs", "Governed plans/jobs are visible; broader executor closure remains."),
            _surface("operations.upgrades", "Upgrades", "PARTIAL", "UpgradePlan + Kubernetes/provider runtimes", "Pinned Cilium Helm upgrade and bounded Kubespray/K3s/RKE2 Kubernetes upgrade paths are executable through trusted workers; disposable-target repeatability remains to be evidenced."),
            _surface("operations.backups", "Backups", "PARTIAL", "Velero + embedded-etcd snapshot runtimes", "Velero backup/schedule/restore is executable, and bounded direct K3s/RKE2 embedded-etcd snapshot is provider-worker backed; Kubespray direct-etcd and provider-specific backup coverage remain open."),
            _surface("operations.recovery", "Recovery", "PARTIAL", "Velero + bounded embedded-etcd recovery", "Explicit-namespace Velero restore and bounded K3s/RKE2 embedded-etcd restore/DR are executable through governed trusted runtimes; Kubespray direct-etcd and full provider-recreation DR remain open."),
            _surface("operations.maintenance", "Maintenance", "PARTIAL", "trusted cluster provider worker", "Bounded provider-service/kubelet restart and reboot maintenance paths are executable on approved existing hosts; broader provider maintenance remains open."),
        ],
    },
    {
        "id": "governance",
        "label": "Governance & Platform",
        "surfaces": [
            _surface("governance.changes", "Changes", "LIVE", "ChangeSets", "Deterministic plans, diffs, risk and state."),
            _surface("governance.approvals", "Approvals", "LIVE", "ChangeSet approvals", "Exact-hash approval state; approval action remains separate-bot-only."),
            _surface("governance.credentials", "Credentials", "LIVE", "Credential Service references", "Metadata-only references; raw credentials are never rendered."),
            _surface("governance.agents", "Agents", "LIVE", "Hermes Agent registry", "Enrollment, heartbeat and task state."),
            _surface("governance.integrations", "Integrations", "LIVE", "integration registry", "Provider/integration metadata and health."),
            _surface("governance.artifact-mirror", "Artifact Mirror", "LIVE", "typed artifact/repository mirror runtime", "ChangeSet-governed bounded mirrors cover blobs, OCI/Helm OCI, exact-tag Git releases, Ansible collections and signed/hash-bound APT/RPM/Python repository snapshots with credential-isolated delivery."),
            _surface("governance.audit", "Audit", "LIVE", "Hermes audit", "Governance and execution audit events."),
            _surface("governance.ai-routing", "AI Routing", "PARTIAL", "shared intent backend/router metadata", "Shared channel contract exists; dedicated routing control UI remains bounded."),
            _surface("governance.settings", "Settings", "PARTIAL", "system/environment configuration", "System/runtime state and environment configuration; secret settings are intentionally absent."),
        ],
    },
]


def contracts() -> dict[str, Any]:
    surfaces = [surface for group in GROUPS for surface in group["surfaces"]]
    return {
        "schema_version": 5,
        "ui_state": UI_STATE,
        "surface_count": len(surfaces),
        "groups": GROUPS,
        "runtime_state_is_separate_from_ui_state": True,
        "credential_material_rendered": False,
        "mutation_ui": "observe-plan-inspect-only",
        "mutation_invariant": "intent -> typed plan -> ChangeSet -> deterministic preview/diff -> risk -> policy -> approval -> exact-hash binding -> constrained execution ticket -> broker/provider/agent -> verification -> audit",
    }
