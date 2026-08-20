from __future__ import annotations

from typing import Any

from .canonical import sha256_hex

CLUSTER_PROVIDERS: dict[str, dict[str, Any]] = {
    "kubespray": {
        "intent": "production-default",
        "execution": "ansible-provider-worker",
        "inventory": "server-registry-derived",
        "networking": "cilium",
        "requirements": ["all-nodes-preflight-pass", "pinned-kubernetes-version", "pinned-host-fingerprints"],
    },
    "k3s": {
        "intent": "lab-edge-lightweight",
        "execution": "typed-k3s-provider-worker",
        "inventory": "server-registry-derived",
        "networking": "cilium",
        "requirements": ["all-nodes-preflight-pass", "pinned-kubernetes-version", "disable-default-flannel-when-cilium"],
    },
    "rke2": {
        "intent": "hardened-production-alternate",
        "execution": "typed-rke2-provider-worker",
        "inventory": "server-registry-derived",
        "networking": "cilium",
        "requirements": ["all-nodes-preflight-pass", "pinned-kubernetes-version", "hardened-profile-explicit"],
    },
}

ADDON_CATALOG: dict[str, dict[str, Any]] = {
    "cilium": {"category": "networking", "required": True, "provider": "helm", "version_pin_required": True},
    "hubble": {"category": "network-visibility", "required": True, "provider": "cilium", "version_pin_required": True},
    "kube-vip": {"category": "control-plane-ha", "required": False, "provider": "bootstrap", "version_pin_required": True},
    "metallb": {"category": "service-load-balancing", "required": False, "provider": "helm", "version_pin_required": True},
    "local-path-storage": {"category": "storage", "required": False, "provider": "helm", "version_pin_required": True},
    "longhorn": {"category": "storage", "required": False, "provider": "helm", "version_pin_required": True},
    "ingress-nginx": {"category": "ingress", "required": False, "provider": "helm", "version_pin_required": True},
    "cert-manager": {"category": "tls-certificates", "required": False, "provider": "helm", "version_pin_required": True},
    "argocd": {"category": "gitops", "required": False, "provider": "helm", "version_pin_required": True},
    "kube-prometheus-stack": {"category": "observability", "required": False, "provider": "helm", "version_pin_required": True},
    "grafana": {"category": "observability-ui", "required": False, "provider": "helm", "version_pin_required": True},
    "loki": {"category": "logs", "required": False, "provider": "helm", "version_pin_required": True},
    "opencost": {"category": "cost-visibility", "required": False, "provider": "helm", "version_pin_required": True},
    "velero": {"category": "backup-restore", "required": False, "provider": "helm", "version_pin_required": True},
    "radar": {"category": "kubernetes-intelligence", "required": True, "provider": "kubernetes", "version_pin_required": True},
    "hermes-agent": {"category": "operations-agent", "required": True, "provider": "helm", "version_pin_required": True},
}

OPERATIONAL_PROFILES: dict[str, dict[str, Any]] = {
    "lab-minimal": {
        "provider": "k3s",
        "topology": {"ha": False, "control_plane_replicas": 1},
        "addons": ["cilium", "hubble", "local-path-storage", "cert-manager", "radar", "hermes-agent"],
        "security": {"baseline": "development"},
    },
    "lab-full": {
        "provider": "k3s",
        "topology": {"ha": True, "control_plane_replicas": 3},
        "addons": ["cilium", "hubble", "longhorn", "ingress-nginx", "cert-manager", "argocd", "kube-prometheus-stack", "grafana", "loki", "radar", "hermes-agent"],
        "security": {"baseline": "development"},
    },
    "production": {
        "provider": "kubespray",
        "topology": {"ha": True, "control_plane_replicas": 3, "etcd": "ha"},
        "addons": ["cilium", "hubble", "kube-vip", "metallb", "ingress-nginx", "cert-manager", "longhorn", "argocd", "kube-prometheus-stack", "grafana", "loki", "opencost", "velero", "radar", "hermes-agent"],
        "security": {"baseline": "production"},
    },
    "production-ha": {
        "provider": "kubespray",
        "topology": {"ha": True, "control_plane_replicas": 3, "etcd": "ha", "topology_spread": True},
        "addons": ["cilium", "hubble", "kube-vip", "metallb", "ingress-nginx", "cert-manager", "longhorn", "argocd", "kube-prometheus-stack", "grafana", "loki", "opencost", "velero", "radar", "hermes-agent"],
        "security": {"baseline": "strict", "pdbs": True, "anti_affinity": True, "backup_policy": "strong"},
    },
    "production-hardened": {
        "provider": "rke2",
        "topology": {"ha": True, "control_plane_replicas": 3, "etcd": "ha", "topology_spread": True},
        "addons": ["cilium", "hubble", "kube-vip", "metallb", "ingress-nginx", "cert-manager", "longhorn", "argocd", "kube-prometheus-stack", "grafana", "loki", "opencost", "velero", "radar", "hermes-agent"],
        "security": {"baseline": "hardened", "cis_style": True, "network_policy_baseline": True, "secure_audit": True},
    },
}


RADAR_CONTRACT: dict[str, Any] = {
    "provider": "radar",
    "mode": "first-class-kubernetes-intelligence",
    "context_modes": {"AUTO": "radar-when-healthy-native-fallback", "RADAR": "require-radar", "NATIVE": "hermes-native-only"},
    "ui": "hermes-native-not-copied-or-iframed",
    "reads": [
        "kubernetes-resources", "search", "applications", "topology", "resource-neighborhood", "issues", "diagnosis",
        "events", "change-timeline", "pod-logs", "workload-logs", "top-cpu-memory", "prometheus", "metric-discovery",
        "prometheus-rules", "helm-history", "argocd", "flux", "cluster-audit", "rbac-visibility", "tls-information",
        "opencost", "image-filesystem-intelligence", "crd-discovery", "compare-diff", "network-information",
    ],
    "mcp_reads": "typed-hermes-interfaces-only",
    "mcp_writes": "translate-to-hermes-changeset",
    "writes": "translate-to-hermes-changeset",
    "governance_bypass": False,
    "credential_exposure": "metadata-only",
}


HUBBLE_CONTRACT: dict[str, Any] = {
    "provider": "hubble",
    "mode": "aggregated-network-visibility",
    "provider_order": {"AUTO": ["cilium-hubble", "istio", "caretta"]},
    "live_windows": ["current", "1m", "15m", "1h", "6h", "24h", "7d-optional"],
    "allowed_for_ai_ui": [
        "windowed-counts", "source-destination-workload", "namespace-pairs", "service-pairs", "protocol-counts", "port-counts",
        "http-method-counts", "http-status-class-counts", "rps", "bytes", "drops", "verdict-counts", "latency-quantiles", "tcp-state-counts",
    ],
    "forbidden_for_ai_ui": ["raw-payloads", "authorization-headers", "secrets", "unredacted-l7-bodies", "per-packet-stream"],
    "authorization": "required",
    "redaction": "required-before-ai-ui",
    "aggregation": "required-before-ai-ui",
    "governance_bypass": False,
}


NATIVE_DIAGNOSTICS: list[dict[str, Any]] = [
    {"id": "nodes.health", "source": "kubernetes-broker", "mode": "read-executable", "description": "Detect NotReady nodes and node pressure conditions."},
    {"id": "pods.health", "source": "kubernetes-broker", "mode": "read-executable", "description": "Detect unhealthy pods and restart hotspots."},
    {"id": "workloads.health", "source": "kubernetes-broker", "mode": "read-executable", "description": "Detect unavailable Deployments, StatefulSets and DaemonSets."},
    {"id": "pods.oom", "source": "kubernetes-broker", "mode": "read-executable", "description": "Detect OOMKilled container states without reading workload environment values."},
    {"id": "resources.cpu-memory", "source": "kubernetes-broker", "mode": "read-executable", "description": "Inspect authorized metrics.k8s.io CPU/memory usage with bounded top-consumer evidence."},
    {"id": "storage.health", "source": "kubernetes-broker", "mode": "read-executable", "description": "Detect PVCs that are not Bound."},
    {"id": "events.correlation", "source": "kubernetes-broker", "mode": "read-executable", "description": "Aggregate Warning events by reason and involved object without exporting event messages."},
    {"id": "network.cilium", "source": "kubernetes-broker", "mode": "read-executable", "description": "Check visible Cilium pod readiness."},
    {"id": "network.hubble", "source": "kubernetes-broker", "mode": "read-executable-redacted", "description": "Verify Hubble Relay through the sanitized broker collector."},
    {"id": "network.dns", "source": "kubernetes-broker", "mode": "read-executable", "description": "Check visible CoreDNS/kube-dns pod readiness."},
    {"id": "network.ingress", "source": "kubernetes-broker", "mode": "read-executable", "description": "Check Ingress class and load-balancer status metadata."},
    {"id": "network.networkpolicy", "source": "kubernetes-broker", "mode": "read-executable", "description": "Identify scoped namespaces with pods and no observed NetworkPolicy."},
    {"id": "security.rbac", "source": "kubernetes-broker", "mode": "read-executable", "description": "Identify broad or sensitive Role/ClusterRole rules."},
    {"id": "security.privileged", "source": "kubernetes-broker", "mode": "read-executable", "description": "Detect privileged containers."},
    {"id": "security.capabilities", "source": "kubernetes-broker", "mode": "read-executable", "description": "Detect dangerous added Linux capabilities."},
    {"id": "security.hostpath", "source": "kubernetes-broker", "mode": "read-executable", "description": "Detect hostPath volumes without returning host paths."},
    {"id": "security.exposed-services", "source": "kubernetes-broker", "mode": "read-executable", "description": "Detect NodePort, LoadBalancer, ExternalName and externalIP Services."},
    {"id": "security.ingress-tls", "source": "kubernetes-broker", "mode": "read-executable", "description": "Identify Ingress resources without TLS configuration."},
    {"id": "security.webhooks", "source": "kubernetes-broker", "mode": "read-executable", "description": "Baseline-check admission webhook failure policy and CA metadata."},
    {"id": "gitops.argocd", "source": "kubernetes-broker", "mode": "read-executable", "description": "Inspect Argo CD Application sync/health status when the CRD is visible."},
    {"id": "rollout.health", "source": "kubernetes-broker", "mode": "read-executable", "description": "Correlate workload readiness and rollout conditions."},
    # Backward-compatible catalog IDs remain executable aliases in the broker.
    {"id": "nodes.not-ready", "source": "kubernetes-broker", "mode": "read-executable", "description": "Compatibility alias for node health."},
    {"id": "workloads.unhealthy", "source": "kubernetes-broker", "mode": "read-executable", "description": "Compatibility alias for workload health."},
    {"id": "pods.restart-hotspots", "source": "kubernetes-broker", "mode": "read-executable", "description": "Compatibility alias for pod health/restarts."},
    {"id": "events.warning-summary", "source": "kubernetes-broker", "mode": "read-executable", "description": "Compatibility alias for Warning-event correlation."},
    {"id": "network.policy-drops", "source": "hubble", "mode": "read-executable-redacted", "description": "Summarize policy drops from sanitized Hubble output."},
    {"id": "storage.pvc-pending", "source": "kubernetes-broker", "mode": "read-executable", "description": "Compatibility alias for PVC health."},
    {"id": "certificates.expiry", "source": "kubernetes-broker", "mode": "read-executable", "description": "Inspect cert-manager Certificate readiness/expiry metadata without private keys."},
    {"id": "backup.recency", "source": "kubernetes-broker", "mode": "read-executable", "description": "Inspect Velero Backup phase metadata when the CRD is visible."},
]


def _require_supported_addons(addons: list[str], versions: dict[str, str]) -> None:
    unknown = sorted(set(addons) - set(ADDON_CATALOG))
    if unknown:
        raise ValueError(f"unsupported add-ons: {', '.join(unknown)}")
    missing = sorted(addon for addon in addons if not str(versions.get(addon) or "").strip())
    if missing:
        raise ValueError(f"explicit version pins required for add-ons: {', '.join(missing)}")


def provisioning_plan(*, cluster: dict[str, Any], blueprint: dict[str, Any], profile: dict[str, Any], node_roles: list[dict[str, Any]], servers: list[dict[str, Any]]) -> dict[str, Any]:
    provider_id = blueprint["provider"]
    provider = CLUSTER_PROVIDERS[provider_id]
    assignments = []
    role_by_server: dict[str, str] = {}
    for role in node_roles:
        for server_id in role["server_ids"]:
            if server_id in role_by_server:
                raise ValueError(f"server {server_id} is assigned to multiple NodeRole resources")
            role_by_server[server_id] = role["role"]
    for server in sorted(servers, key=lambda item: item["id"]):
        role = role_by_server.get(server["id"])
        if not role:
            raise ValueError(f"server {server['id']} has no NodeRole assignment")
        if server["preflight_status"] != "PASS":
            raise ValueError(f"server {server['id']} must have PASS preflight status")
        assignments.append({
            "server_id": server["id"],
            "hostname": server["hostname"],
            "management_ip": server["management_ip"],
            "role": role,
            "preflight_status": server["preflight_status"],
            "host_fingerprint": server["host_fingerprint"],
        })
    control_planes = [item for item in assignments if item["role"] in {"control-plane", "control-plane-worker"}]
    if not control_planes:
        raise ValueError("at least one control-plane capable node is required")
    required_addons = ["cilium", "hermes-agent"]
    if blueprint["hubble_enabled"]:
        required_addons.append("hubble")
    if blueprint["radar_enabled"]:
        required_addons.append("radar")
    addons = list(dict.fromkeys([*required_addons, *blueprint["addon_defaults"]]))
    _require_supported_addons(addons, blueprint["addon_versions"])
    control_plane_hosts = [item["hostname"] for item in assignments if item["role"] in {"control-plane", "control-plane-worker"}]
    worker_hosts = [item["hostname"] for item in assignments if item["role"] in {"worker", "control-plane-worker"}]
    if provider_id == "kubespray":
        provider_payload = {
            "kind": "KubesprayExecutionSpec",
            "playbook": "cluster.yml",
            "kubespray_version": blueprint["provider_version"],
            "container_runtime": "containerd",
            "inventory": {
                "kube_control_plane": control_plane_hosts,
                "etcd": control_plane_hosts,
                "kube_node": worker_hosts,
            },
            "network_plugin": "cilium",
            "control_plane_load_balancer": profile["overrides"].get("control_plane_load_balancer", "kube-vip"),
            "service_load_balancer": profile["overrides"].get("service_load_balancer", "metallb"),
            "upgrade_workflow": True,
            "node_lifecycle": ["add", "remove"],
            "recoverable_stages": True,
            "host_key_policy": "pinned-fingerprint-required",
            "arbitrary_ansible_extra_args": False,
        }
    elif provider_id == "k3s":
        provider_payload = {
            "kind": "K3sExecutionSpec",
            "provider_version": blueprint["provider_version"],
            "servers": control_plane_hosts,
            "agents": [item["hostname"] for item in assignments if item["role"] == "worker"],
            "external_cni": "cilium",
            "ha": len(control_plane_hosts) > 1,
            "disable_default_cni": True,
            "token_delivery": "credential-service-to-provider-worker-only",
            "arbitrary_install_script": False,
        }
    else:
        provider_payload = {
            "kind": "RKE2ExecutionSpec",
            "provider_version": blueprint["provider_version"],
            "servers": control_plane_hosts,
            "agents": [item["hostname"] for item in assignments if item["role"] == "worker"],
            "external_cni": "cilium",
            "disable_default_cni": True,
            "hardened_profile_required": True,
            "secrets_encryption": True,
            "protect_kernel_defaults": True,
            "token_delivery": "credential-service-to-provider-worker-only",
            "arbitrary_install_script": False,
        }
    plan = {
        "schema_version": 3,
        "kind": "ClusterProvisioningPlan",
        "cluster_id": cluster["id"],
        "cluster_name": cluster["name"],
        "provider": provider_id,
        "provider_version": blueprint["provider_version"],
        "provider_contract": provider,
        "kubernetes_version": blueprint["kubernetes_version"],
        "network_plugin": blueprint["network_plugin"],
        "hubble_enabled": bool(blueprint["hubble_enabled"]),
        "radar_enabled": bool(blueprint["radar_enabled"]),
        "topology": blueprint["topology"],
        "profile_overrides": profile["overrides"],
        "nodes": assignments,
        "provider_payload": provider_payload,
        "addons": [{"id": name, "version": blueprint["addon_versions"][name], **ADDON_CATALOG[name]} for name in addons],
        "stages": ["validate", "render-inventory", "install-runtime", "bootstrap-control-plane", "join-workers", "install-cilium", "enable-hubble", "install-radar", "verify"],
        "mutation_gate": "changeset-exact-hash-approval",
    }
    plan["plan_hash"] = sha256_hex(plan)
    return plan


def addon_plan(*, cluster: dict[str, Any], addons: list[str], versions: dict[str, str], configuration: dict[str, Any]) -> dict[str, Any]:
    _require_supported_addons(addons, versions)
    ordered = [name for name in ADDON_CATALOG if name in addons]
    plan = {
        "schema_version": 3,
        "kind": "AddonPlan",
        "cluster_id": cluster["id"],
        "addons": [{"id": name, "version": versions[name], **ADDON_CATALOG[name], "configuration": configuration.get(name, {})} for name in ordered],
        "dependency_order": ordered,
        "mutation_gate": "changeset-exact-hash-approval",
    }
    plan["plan_hash"] = sha256_hex(plan)
    return plan


def upgrade_plan(*, cluster: dict[str, Any], provider: str, target_version: str, strategy: dict[str, Any]) -> dict[str, Any]:
    plan = {
        "schema_version": 3,
        "kind": "UpgradePlan",
        "cluster_id": cluster["id"],
        "provider": provider,
        "from_version": cluster["kubernetes_version"],
        "to_version": target_version,
        "strategy": strategy,
        "stages": ["preflight", "backup", "control-plane", "workers", "addons-compatibility", "verify"],
        "rollback_boundary": "provider-specific-supported-boundary",
        "mutation_gate": "changeset-exact-hash-approval",
    }
    plan["plan_hash"] = sha256_hex(plan)
    return plan


def backup_plan(*, cluster: dict[str, Any], provider: str, schedule: str, retention_count: int, scope: dict[str, Any]) -> dict[str, Any]:
    plan = {
        "schema_version": 3,
        "kind": "BackupPlan",
        "cluster_id": cluster["id"],
        "provider": provider,
        "schedule": schedule,
        "retention_count": retention_count,
        "scope": scope,
        "restore_verification": True,
        "mutation_gate": "changeset-exact-hash-approval",
    }
    plan["plan_hash"] = sha256_hex(plan)
    return plan
