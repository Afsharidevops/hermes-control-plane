from __future__ import annotations

from copy import deepcopy
from typing import Any
from urllib.parse import urlparse

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




BLUEPRINT_ARTIFACT_COMPONENT_LABEL = "blueprint_component"
BLUEPRINT_ARTIFACT_NAME_LABEL = "blueprint_name"
BLUEPRINT_ARTIFACT_KEY_LABEL = "dependency_key"
BLUEPRINT_ARTIFACT_DEPENDS_ON_LABEL = "depends_on"


def blueprint_required_artifact_components(blueprint: dict[str, Any]) -> list[dict[str, str]]:
    required_addons = ["cilium", "hermes-agent"]
    if bool(blueprint.get("hubble_enabled")):
        required_addons.append("hubble")
    if bool(blueprint.get("radar_enabled")):
        required_addons.append("radar")
    required_addons.extend(list(blueprint.get("addon_defaults") or []))
    ordered_addons = [name for name in ADDON_CATALOG if name in set(required_addons)]
    versions = blueprint.get("addon_versions") if isinstance(blueprint.get("addon_versions"), dict) else {}
    required = [
        {"component": "provider", "name": str(blueprint.get("provider") or ""), "version": str(blueprint.get("provider_version") or "")},
        {"component": "kubernetes", "name": "kubernetes", "version": str(blueprint.get("kubernetes_version") or "")},
    ]
    required.extend({"component": "addon", "name": name, "version": str(versions.get(name) or "")} for name in ordered_addons)
    return required


def _artifact_offline_reference(artifact: dict[str, Any]) -> tuple[str | None, str | None]:
    reference = str(artifact.get("destination") or "")
    parsed = urlparse(reference)
    if parsed.username is not None or parsed.password is not None:
        return None, "offline destination contains embedded credentials"
    if parsed.scheme not in {"file", "oci"}:
        return None, "offline destination must use file:// or oci://"
    if parsed.query or parsed.fragment:
        return None, "offline destination must not contain query or fragment"
    if parsed.scheme == "file" and (parsed.netloc or not parsed.path.startswith("/")):
        return None, "offline file destination must be an absolute local file:// URI"
    if parsed.scheme == "oci" and (not parsed.netloc or not parsed.path.strip("/")):
        return None, "offline OCI destination must include registry and repository"
    return reference, None


def resolve_blueprint_artifact_manifest(*, blueprint: dict[str, Any], artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    required = blueprint_required_artifact_components(blueprint)
    required_map = {(item["component"], item["name"]): item for item in required}
    bound_ids = list(blueprint.get("artifact_dependencies") or [])
    issues: list[dict[str, Any]] = []
    if len(bound_ids) != len(set(bound_ids)):
        issues.append({"code": "duplicate-binding", "summary": "blueprint artifact dependency IDs must be unique"})

    by_id = {str(item.get("id") or ""): item for item in artifacts}
    resolved: list[dict[str, Any]] = []
    coverage: dict[tuple[str, str], int] = {key: 0 for key in required_map}
    dependency_keys: set[tuple[str, str, str]] = set()

    for artifact_id in bound_ids:
        artifact = by_id.get(str(artifact_id))
        if artifact is None:
            issues.append({"code": "missing-artifact", "artifact_id": artifact_id, "summary": "bound artifact does not exist"})
            continue
        labels = artifact.get("labels") if isinstance(artifact.get("labels"), dict) else {}
        component = str(labels.get(BLUEPRINT_ARTIFACT_COMPONENT_LABEL) or "")
        name = str(labels.get(BLUEPRINT_ARTIFACT_NAME_LABEL) or "")
        dependency_key = str(labels.get(BLUEPRINT_ARTIFACT_KEY_LABEL) or "")
        required_item = required_map.get((component, name))
        if required_item is None:
            issues.append({"code": "unexpected-component", "artifact_id": artifact_id, "summary": "artifact labels do not match a required blueprint component"})
            continue
        if not dependency_key or len(dependency_key) > 120:
            issues.append({"code": "invalid-dependency-key", "artifact_id": artifact_id, "summary": "dependency_key label is required and must be at most 120 characters"})
            continue
        key_tuple = (component, name, dependency_key)
        if key_tuple in dependency_keys:
            issues.append({"code": "duplicate-dependency-key", "artifact_id": artifact_id, "summary": "dependency_key must be unique within a blueprint component"})
            continue
        dependency_keys.add(key_tuple)
        coverage[(component, name)] += 1

        artifact_version = str(artifact.get("version") or "")
        if artifact_version != required_item["version"]:
            issues.append({
                "code": "version-mismatch",
                "artifact_id": artifact_id,
                "summary": f"artifact version {artifact_version!r} does not match required {required_item['version']!r}",
            })

        reference, reference_error = _artifact_offline_reference(artifact)
        if reference_error:
            issues.append({"code": "unsafe-offline-reference", "artifact_id": artifact_id, "summary": reference_error})

        verification = artifact.get("verification") if isinstance(artifact.get("verification"), dict) else {}
        mirrored = verification.get("status") == "PASS" and verification.get("sync_state") == "MIRRORED"
        if not mirrored:
            issues.append({"code": "artifact-not-mirrored", "artifact_id": artifact_id, "summary": "artifact has no successful mirrored verification"})

        raw_depends = str(labels.get(BLUEPRINT_ARTIFACT_DEPENDS_ON_LABEL) or "")
        depends_on = [item.strip() for item in raw_depends.split(",") if item.strip()]
        if len(depends_on) != len(set(depends_on)):
            issues.append({"code": "duplicate-edge", "artifact_id": artifact_id, "summary": "depends_on contains duplicate artifact IDs"})

        resolved.append({
            "artifact_id": str(artifact_id),
            "component": component,
            "name": name,
            "dependency_key": dependency_key,
            "kind": str(artifact.get("kind") or ""),
            "version": artifact_version,
            "digest": str(artifact.get("digest") or ""),
            "offline_reference": reference,
            "depends_on": depends_on,
            "mirrored": mirrored,
            "verification_id": verification.get("verification_id"),
            "observed_at": verification.get("observed_at"),
        })

    for key, item in required_map.items():
        if coverage[key] == 0:
            issues.append({"code": "missing-component", "component": item["component"], "name": item["name"], "version": item["version"], "summary": "no artifact is bound for required blueprint component"})

    resolved_by_id = {item["artifact_id"]: item for item in resolved}
    for item in resolved:
        for dependency_id in item["depends_on"]:
            if dependency_id == item["artifact_id"]:
                issues.append({"code": "self-cycle", "artifact_id": item["artifact_id"], "summary": "artifact cannot depend on itself"})
            elif dependency_id not in resolved_by_id:
                issues.append({"code": "unbound-edge", "artifact_id": item["artifact_id"], "dependency_id": dependency_id, "summary": "depends_on references an artifact outside the bound set"})

    indegree = {artifact_id: 0 for artifact_id in resolved_by_id}
    followers = {artifact_id: [] for artifact_id in resolved_by_id}
    for item in resolved:
        for dependency_id in item["depends_on"]:
            if dependency_id in resolved_by_id and dependency_id != item["artifact_id"]:
                indegree[item["artifact_id"]] += 1
                followers[dependency_id].append(item["artifact_id"])

    def sort_key(artifact_id: str) -> tuple[str, str, str, str]:
        item = resolved_by_id[artifact_id]
        component_rank = {"provider": "0", "kubernetes": "1", "addon": "2"}.get(item["component"], "9")
        return (component_rank, item["name"], item["dependency_key"], artifact_id)

    ready = sorted([artifact_id for artifact_id, degree in indegree.items() if degree == 0], key=sort_key)
    ordered_ids: list[str] = []
    while ready:
        artifact_id = ready.pop(0)
        ordered_ids.append(artifact_id)
        for follower in sorted(followers[artifact_id], key=sort_key):
            indegree[follower] -= 1
            if indegree[follower] == 0:
                ready.append(follower)
                ready.sort(key=sort_key)
    if len(ordered_ids) != len(resolved_by_id):
        cycle_ids = sorted([artifact_id for artifact_id, degree in indegree.items() if degree > 0])
        issues.append({"code": "dependency-cycle", "artifact_ids": cycle_ids, "summary": "artifact dependency graph contains a cycle"})
        ordered_ids.extend(artifact_id for artifact_id in sorted(resolved_by_id, key=sort_key) if artifact_id not in ordered_ids)

    ordered = [resolved_by_id[artifact_id] for artifact_id in ordered_ids]
    issue_artifacts = {str(issue.get("artifact_id")) for issue in issues if issue.get("artifact_id")}
    resume_from = next((item["artifact_id"] for item in ordered if not item["mirrored"] or item["artifact_id"] in issue_artifacts), None)
    state = "READY" if not issues else "BLOCKED"
    manifest = {
        "schema_version": 1,
        "kind": "ClusterBlueprintArtifactManifest",
        "blueprint_id": str(blueprint.get("id") or ""),
        "blueprint_name": str(blueprint.get("name") or ""),
        "state": state,
        "required_components": required,
        "bound_artifact_ids": bound_ids,
        "dependency_order": ordered,
        "issues": issues,
        "resume_from_artifact_id": resume_from,
        "offline_reference_selection": "verified-destination-only",
        "credential_material_in_manifest": False,
        "provisioner_rewrite_applied": False,
    }
    manifest["manifest_hash"] = sha256_hex(manifest)
    return manifest



PXE_ARTIFACT_ROLES = {"kernel", "initrd", "rootfs", "installer", "unattended"}
PXE_REQUIRED_ARTIFACT_ROLES = {"kernel", "initrd", "unattended"}


def resolve_pxe_artifact_manifest(*, role_bindings: dict[str, str], artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(role_bindings, dict):
        raise ValueError("PXE artifact role bindings must be an object")
    unknown_roles = sorted(set(role_bindings) - PXE_ARTIFACT_ROLES)
    if unknown_roles:
        raise ValueError("unsupported PXE artifact role(s): " + ", ".join(unknown_roles))
    missing_roles = sorted(PXE_REQUIRED_ARTIFACT_ROLES - set(role_bindings))
    if missing_roles:
        raise ValueError("PXE artifact bindings require: " + ", ".join(missing_roles))
    if len(set(role_bindings.values())) != len(role_bindings):
        raise ValueError("PXE artifact IDs must be unique across roles")

    by_id = {str(item.get("id") or ""): item for item in artifacts}
    issues: list[dict[str, Any]] = []
    resolved: dict[str, dict[str, Any]] = {}
    for role in sorted(role_bindings):
        artifact_id = str(role_bindings[role] or "")
        artifact = by_id.get(artifact_id)
        if artifact is None:
            issues.append({"code": "missing-artifact", "role": role, "artifact_id": artifact_id, "summary": "bound PXE artifact does not exist"})
            continue
        verification = artifact.get("verification") if isinstance(artifact.get("verification"), dict) else {}
        mirrored = verification.get("status") == "PASS" and verification.get("sync_state") == "MIRRORED"
        if not mirrored:
            issues.append({"code": "artifact-not-mirrored", "role": role, "artifact_id": artifact_id, "summary": "PXE artifact has no successful mirrored verification"})
        reference, reference_error = _artifact_offline_reference(artifact)
        if reference_error:
            issues.append({"code": "unsafe-offline-reference", "role": role, "artifact_id": artifact_id, "summary": reference_error})
        elif not str(reference).startswith("file:///"):
            issues.append({"code": "unsupported-pxe-reference", "role": role, "artifact_id": artifact_id, "summary": "PXE runtime requires an exact verified local file:// mirror destination"})
        digest = str(artifact.get("digest") or "")
        if not digest.startswith("sha256:") or len(digest) != 71:
            issues.append({"code": "invalid-digest", "role": role, "artifact_id": artifact_id, "summary": "PXE artifact must be bound by an exact SHA-256 digest"})
        resolved[role] = {
            "artifact_id": artifact_id,
            "kind": str(artifact.get("kind") or ""),
            "version": str(artifact.get("version") or ""),
            "digest": digest,
            "offline_reference": reference,
            "mirrored": mirrored,
            "verification_id": verification.get("verification_id"),
            "observed_at": verification.get("observed_at"),
        }

    manifest = {
        "schema_version": 1,
        "kind": "PXEProvisioningArtifactManifest",
        "state": "READY" if not issues else "BLOCKED",
        "role_bindings": {role: str(role_bindings[role]) for role in sorted(role_bindings)},
        "artifacts": resolved,
        "issues": issues,
        "offline_reference_selection": "verified-destination-only",
        "credential_material_in_manifest": False,
        "public_network_required": False,
    }
    manifest["manifest_hash"] = sha256_hex(manifest)
    return manifest


def pxe_artifact_supply(manifest: dict[str, Any]) -> dict[str, Any]:
    if manifest.get("kind") != "PXEProvisioningArtifactManifest" or manifest.get("state") != "READY" or manifest.get("issues"):
        raise ValueError("PXE artifact manifest must be READY before unattended provisioning can be planned")
    manifest_hash = str(manifest.get("manifest_hash") or "")
    unsigned = deepcopy(manifest)
    unsigned.pop("manifest_hash", None)
    if not manifest_hash or sha256_hex(unsigned) != manifest_hash:
        raise ValueError("PXE artifact manifest hash verification failed")
    if manifest.get("credential_material_in_manifest") is not False or manifest.get("public_network_required") is not False:
        raise ValueError("PXE artifact manifest violates the offline credential/network boundary")
    artifacts = manifest.get("artifacts") if isinstance(manifest.get("artifacts"), dict) else {}
    if not PXE_REQUIRED_ARTIFACT_ROLES.issubset(artifacts):
        raise ValueError("PXE artifact manifest is missing required roles")
    safe_artifacts: dict[str, dict[str, Any]] = {}
    for role in sorted(artifacts):
        item = artifacts[role]
        if role not in PXE_ARTIFACT_ROLES or not isinstance(item, dict) or item.get("mirrored") is not True:
            raise ValueError("PXE artifact manifest contains an invalid role entry")
        reference = str(item.get("offline_reference") or "")
        parsed = urlparse(reference)
        if parsed.scheme != "file" or parsed.netloc or not parsed.path.startswith("/") or parsed.query or parsed.fragment:
            raise ValueError("PXE runtime requires exact local verified file:// artifact references")
        digest = str(item.get("digest") or "")
        if not digest.startswith("sha256:") or len(digest) != 71:
            raise ValueError("PXE artifact supply contains an invalid digest")
        safe_artifacts[role] = {
            "artifact_id": str(item.get("artifact_id") or ""),
            "kind": str(item.get("kind") or ""),
            "version": str(item.get("version") or ""),
            "digest": digest,
            "offline_reference": reference,
        }
    supply = {
        "mode": "pxe-ready-manifest-bound",
        "manifest_hash": manifest_hash,
        "artifacts": safe_artifacts,
        "credential_material_in_plan": False,
        "public_network_required": False,
        "provisioner_rewrite_applied": True,
    }
    supply["supply_hash"] = sha256_hex(supply)
    return supply

def _require_supported_addons(addons: list[str], versions: dict[str, str]) -> None:
    unknown = sorted(set(addons) - set(ADDON_CATALOG))
    if unknown:
        raise ValueError(f"unsupported add-ons: {', '.join(unknown)}")
    missing = sorted(addon for addon in addons if not str(versions.get(addon) or "").strip())
    if missing:
        raise ValueError(f"explicit version pins required for add-ons: {', '.join(missing)}")


def offline_artifact_supply(artifact_manifest: dict[str, Any]) -> dict[str, Any]:
    if artifact_manifest.get("state") != "READY" or artifact_manifest.get("issues"):
        raise ValueError("cluster blueprint artifact manifest must be READY before offline provisioning can be planned")
    manifest_hash = str(artifact_manifest.get("manifest_hash") or "")
    unsigned_manifest = deepcopy(artifact_manifest)
    unsigned_manifest.pop("manifest_hash", None)
    if not manifest_hash or sha256_hex(unsigned_manifest) != manifest_hash:
        raise ValueError("cluster blueprint artifact manifest hash verification failed")
    if artifact_manifest.get("credential_material_in_manifest") is not False:
        raise ValueError("cluster blueprint artifact manifest must attest credential-free content")
    if artifact_manifest.get("offline_reference_selection") != "verified-destination-only":
        raise ValueError("cluster blueprint artifact manifest must use verified destination references only")

    offline_artifacts: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for item in artifact_manifest.get("dependency_order") or []:
        artifact_id = str(item.get("artifact_id") or "")
        if not artifact_id or artifact_id in seen_ids:
            raise ValueError("cluster blueprint artifact manifest contains duplicate or empty artifact IDs")
        seen_ids.add(artifact_id)
        if item.get("mirrored") is not True:
            raise ValueError(f"artifact {artifact_id} is not verified mirrored content")
        reference = str(item.get("offline_reference") or "")
        parsed = urlparse(reference)
        if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise ValueError(f"artifact {artifact_id} has an unsafe offline reference")
        if parsed.scheme == "file":
            if parsed.netloc or not parsed.path.startswith("/"):
                raise ValueError(f"artifact {artifact_id} has an invalid offline file reference")
        elif parsed.scheme == "oci":
            if not parsed.netloc or not parsed.path.strip("/"):
                raise ValueError(f"artifact {artifact_id} has an invalid offline OCI reference")
        else:
            raise ValueError(f"artifact {artifact_id} has an unsupported offline reference scheme")
        digest = str(item.get("digest") or "")
        if not digest.startswith("sha256:") or len(digest) != 71:
            raise ValueError(f"artifact {artifact_id} must be bound by an exact SHA-256 digest")
        offline_artifacts.append({
            "artifact_id": artifact_id,
            "component": str(item.get("component") or ""),
            "name": str(item.get("name") or ""),
            "dependency_key": str(item.get("dependency_key") or ""),
            "kind": str(item.get("kind") or ""),
            "version": str(item.get("version") or ""),
            "digest": digest,
            "offline_reference": reference,
            "depends_on": list(item.get("depends_on") or []),
        })
    if not offline_artifacts:
        raise ValueError("cluster blueprint artifact manifest contains no resolved dependencies")
    return {
        "mode": "offline-manifest-bound",
        "manifest_hash": manifest_hash,
        "dependency_order": offline_artifacts,
        "offline_reference_selection": "verified-destination-only",
        "credential_material_in_plan": False,
        "provisioner_rewrite_applied": True,
        "rewrite_contract": {
            "file_artifacts": "provider-worker-local-mirror-path",
            "oci_artifacts": "offline-registry-reference",
            "repository_endpoints": "provider-worker-runtime-config",
            "credential_delivery": "worker-only-mounted-secrets",
            "public_network_required": False,
        },
    }


def _bind_ready_artifact_manifest(plan: dict[str, Any], artifact_manifest: dict[str, Any]) -> dict[str, Any]:
    supply = offline_artifact_supply(artifact_manifest)
    bound = deepcopy(plan)
    bound["schema_version"] = max(int(bound.get("schema_version") or 0), 5)
    bound["artifact_supply"] = supply
    provider_payload = dict(bound.get("provider_payload") or {})
    provider_payload["offline_artifact_manifest_hash"] = supply["manifest_hash"]
    provider_payload["offline_artifacts"] = supply["dependency_order"]
    provider_payload["offline_reference_mode"] = "verified-mirror-destinations"
    provider_payload["provisioner_rewrite_applied"] = True
    provider_payload["offline_execution_contract"] = {
        "public_network_required": False,
        "arbitrary_shell": False,
        "arbitrary_ssh_command": False,
        "credential_material_in_plan": False,
    }
    bound["provider_payload"] = provider_payload
    bound.pop("plan_hash", None)
    bound["plan_hash"] = sha256_hex(bound)
    return bound


def provisioning_plan(*, cluster: dict[str, Any], blueprint: dict[str, Any], profile: dict[str, Any], node_roles: list[dict[str, Any]], servers: list[dict[str, Any]], artifact_manifest: dict[str, Any] | None = None) -> dict[str, Any]:
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
        assignment = {
            "server_id": server["id"],
            "hostname": server["hostname"],
            "management_ip": server["management_ip"],
            "ssh_port": int(server.get("ssh_port") or 22),
            "ssh_user": server.get("ssh_user"),
            "credential_ref": server.get("credential_ref"),
            "status": server.get("status", "configured"),
            "role": role,
            "preflight_status": server["preflight_status"],
            "host_fingerprint": server["host_fingerprint"],
        }
        assignment["snapshot_hash"] = sha256_hex(assignment)
        assignments.append(assignment)
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
    if artifact_manifest is not None:
        plan = _bind_ready_artifact_manifest(plan, artifact_manifest)
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
