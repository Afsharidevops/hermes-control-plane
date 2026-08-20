from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

MAX_EVIDENCE_ITEMS = 50
RESTART_HOTSPOT = 5
DANGEROUS_CAPABILITIES = {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH"}
DANGEROUS_RBAC_RESOURCES = {"secrets", "pods/exec", "pods/attach", "serviceaccounts/token", "nodes/proxy"}
DANGEROUS_RBAC_VERBS = {"*", "impersonate", "bind", "escalate"}

DEFAULT_CHECK_IDS = (
    "nodes.health",
    "pods.health",
    "workloads.health",
    "pods.oom",
    "resources.cpu-memory",
    "storage.health",
    "events.correlation",
    "network.cilium",
    "network.hubble",
    "network.dns",
    "network.ingress",
    "network.networkpolicy",
    "security.rbac",
    "security.privileged",
    "security.capabilities",
    "security.hostpath",
    "security.exposed-services",
    "security.ingress-tls",
    "security.webhooks",
    "gitops.argocd",
    "rollout.health",
)

CHECK_IDS = DEFAULT_CHECK_IDS + (
    # Backward-compatible dev.3 diagnostic catalog IDs.
    "nodes.not-ready",
    "workloads.unhealthy",
    "pods.restart-hotspots",
    "events.warning-summary",
    "network.policy-drops",
    "storage.pvc-pending",
    "certificates.expiry",
    "backup.recency",
)

ALIASES = {
    "nodes.not-ready": "nodes.health",
    "workloads.unhealthy": "workloads.health",
    "pods.restart-hotspots": "pods.health",
    "events.warning-summary": "events.correlation",
    "storage.pvc-pending": "storage.health",
}


def _items(bundle: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = bundle.get(key) or {}
    items = value.get("items") if isinstance(value, dict) else []
    return [x for x in (items or []) if isinstance(x, dict)]


def _error(bundle: dict[str, Any], key: str) -> str | None:
    value = bundle.get(key) or {}
    if not isinstance(value, dict):
        return "collector returned invalid data"
    err = value.get("error")
    return str(err)[:500] if err else None


def _collector_skip(bundle: dict[str, Any], key: str, check_id: str, label: str) -> dict[str, Any] | None:
    err = _error(bundle, key)
    if not err:
        return None
    return _finding(check_id, "SKIP", f"{label} collector is unavailable or denied by Kubernetes RBAC/target scope.", {"collector_error": err})


def _meta(item: dict[str, Any]) -> tuple[str, str]:
    meta = item.get("metadata") or {}
    return str(meta.get("namespace") or ""), str(meta.get("name") or "")


def _id(item: dict[str, Any], *, include_kind: bool = False) -> str:
    ns, name = _meta(item)
    kind = str(item.get("kind") or "")
    base = f"{ns}/{name}" if ns else name
    return f"{kind}/{base}" if include_kind and kind else base


def _bounded(values: list[Any]) -> list[Any]:
    return values[:MAX_EVIDENCE_ITEMS]


def _finding(check_id: str, status: str, summary: str, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "id": check_id,
        "status": status,
        "summary": summary[:1000],
        "evidence": evidence or {},
    }


def _condition_true(item: dict[str, Any], kind: str) -> bool:
    for cond in ((item.get("status") or {}).get("conditions") or []):
        if isinstance(cond, dict) and str(cond.get("type")) == kind:
            return str(cond.get("status")).lower() == "true"
    return False


def _nodes(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    if (err := _error(bundle, "nodes")):
        return _finding(check_id, "SKIP", "Node diagnostics require cluster_read target scope.", {"collector_error": err})
    bad = []
    for node in _items(bundle, "nodes"):
        reasons = []
        if not _condition_true(node, "Ready"):
            reasons.append("NotReady")
        for condition in ("MemoryPressure", "DiskPressure", "PIDPressure", "NetworkUnavailable"):
            if _condition_true(node, condition):
                reasons.append(condition)
        if reasons:
            bad.append({"node": _meta(node)[1], "conditions": reasons})
    return _finding(check_id, "FAIL" if bad else "PASS", f"{len(bad)} unhealthy node(s) detected." if bad else "All authorized nodes report healthy readiness conditions.", {"unhealthy_nodes": _bounded(bad), "node_count": len(_items(bundle, "nodes"))})


def _pod_ready(pod: dict[str, Any]) -> bool:
    phase = str((pod.get("status") or {}).get("phase") or "")
    if phase == "Succeeded":
        return True
    return phase == "Running" and _condition_true(pod, "Ready")


def _pods(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    if skipped := _collector_skip(bundle, "pods", check_id, "Pod"):
        return skipped
    unhealthy = []
    restarts = []
    for pod in _items(bundle, "pods"):
        if not _pod_ready(pod):
            unhealthy.append({"pod": _id(pod), "phase": str((pod.get("status") or {}).get("phase") or "Unknown")})
        total = sum(int(x.get("restartCount") or 0) for x in ((pod.get("status") or {}).get("containerStatuses") or []) if isinstance(x, dict))
        if total >= RESTART_HOTSPOT:
            restarts.append({"pod": _id(pod), "restart_count": total})
    status = "FAIL" if unhealthy else ("WARN" if restarts else "PASS")
    summary = f"{len(unhealthy)} unhealthy pod(s); {len(restarts)} restart hotspot(s)."
    return _finding(check_id, status, summary, {"unhealthy_pods": _bounded(unhealthy), "restart_hotspots": _bounded(sorted(restarts, key=lambda x: (-x["restart_count"], x["pod"])))})


def _workload_issue(item: dict[str, Any]) -> dict[str, Any] | None:
    kind = str(item.get("kind") or "")
    status = item.get("status") or {}
    spec = item.get("spec") or {}
    desired = int(spec.get("replicas") or 1)
    if kind == "DaemonSet":
        desired = int(status.get("desiredNumberScheduled") or 0)
        ready = int(status.get("numberReady") or 0)
        available = int(status.get("numberAvailable") or 0)
    else:
        ready = int(status.get("readyReplicas") or 0)
        available = int(status.get("availableReplicas") or 0)
    if ready < desired or available < desired:
        return {"workload": _id(item, include_kind=True), "desired": desired, "ready": ready, "available": available}
    return None


def _workloads(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    if skipped := _collector_skip(bundle, "workloads", check_id, "Workload"):
        return skipped
    issues = [x for x in (_workload_issue(item) for item in _items(bundle, "workloads")) if x]
    return _finding(check_id, "FAIL" if issues else "PASS", f"{len(issues)} unavailable workload(s) detected." if issues else "Authorized workloads meet desired readiness/availability.", {"unavailable_workloads": _bounded(issues), "workload_count": len(_items(bundle, "workloads"))})


def _oom(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    if skipped := _collector_skip(bundle, "pods", check_id, "Pod"):
        return skipped
    hits = []
    for pod in _items(bundle, "pods"):
        for cs in ((pod.get("status") or {}).get("containerStatuses") or []):
            if not isinstance(cs, dict):
                continue
            states = [cs.get("state") or {}, cs.get("lastState") or {}]
            if any(str((state.get("terminated") or {}).get("reason") or "") == "OOMKilled" for state in states):
                hits.append({"pod": _id(pod), "container": str(cs.get("name") or ""), "restart_count": int(cs.get("restartCount") or 0)})
    return _finding(check_id, "WARN" if hits else "PASS", f"{len(hits)} OOM-killed container(s) observed." if hits else "No OOMKilled container state observed in authorized pods.", {"oom_killed": _bounded(hits)})


def _quantity(value: Any) -> float:
    raw = str(value or "0").strip()
    suffixes = {"n": 1e-9, "u": 1e-6, "m": 1e-3, "Ki": 1024.0, "Mi": 1024.0**2, "Gi": 1024.0**3, "Ti": 1024.0**4, "K": 1000.0, "M": 1000.0**2, "G": 1000.0**3}
    for suffix in sorted(suffixes, key=len, reverse=True):
        if raw.endswith(suffix):
            try:
                return float(raw[:-len(suffix)]) * suffixes[suffix]
            except ValueError:
                return 0.0
    try:
        return float(raw)
    except ValueError:
        return 0.0


def _metrics(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    pod_metrics = _items(bundle, "metrics_pods")
    node_metrics = _items(bundle, "metrics_nodes")
    errors = [x for x in (_error(bundle, "metrics_pods"), _error(bundle, "metrics_nodes")) if x]
    if not pod_metrics and not node_metrics:
        return _finding(check_id, "SKIP", "Kubernetes metrics API is unavailable or outside target scope.", {"collector_errors": errors})
    pods = []
    for item in pod_metrics:
        cpu = sum(_quantity((c.get("usage") or {}).get("cpu")) for c in (item.get("containers") or []) if isinstance(c, dict))
        memory = sum(_quantity((c.get("usage") or {}).get("memory")) for c in (item.get("containers") or []) if isinstance(c, dict))
        pods.append({"pod": _id(item), "cpu_cores": round(cpu, 6), "memory_bytes": int(memory)})
    top_cpu = sorted(pods, key=lambda x: (-x["cpu_cores"], x["pod"]))[:10]
    top_mem = sorted(pods, key=lambda x: (-x["memory_bytes"], x["pod"]))[:10]
    return _finding(check_id, "WARN" if errors else "PASS", f"Metrics collected for {len(pod_metrics)} pod(s) and {len(node_metrics)} node(s).", {"top_pod_cpu": top_cpu, "top_pod_memory": top_mem, "collector_errors": errors})


def _storage(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    if skipped := _collector_skip(bundle, "pvcs", check_id, "PVC"):
        return skipped
    pending = []
    for pvc in _items(bundle, "pvcs"):
        phase = str((pvc.get("status") or {}).get("phase") or "Unknown")
        if phase != "Bound":
            pending.append({"pvc": _id(pvc), "phase": phase, "storage_class": str((pvc.get("spec") or {}).get("storageClassName") or "")})
    return _finding(check_id, "WARN" if pending else "PASS", f"{len(pending)} PVC(s) are not Bound." if pending else "Authorized PVCs are Bound.", {"unbound_pvcs": _bounded(pending), "pvc_count": len(_items(bundle, "pvcs"))})


def _events(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    if skipped := _collector_skip(bundle, "events", check_id, "Event"):
        return skipped
    counts: Counter[tuple[str, str, str, str]] = Counter()
    for event in _items(bundle, "events"):
        if str(event.get("type") or "").lower() != "warning":
            continue
        ns, _ = _meta(event)
        involved = event.get("involvedObject") or event.get("regarding") or {}
        counts[(ns, str(event.get("reason") or "Unknown"), str(involved.get("kind") or ""), str(involved.get("name") or ""))] += int(event.get("count") or 1)
    rows = [{"namespace": k[0], "reason": k[1], "kind": k[2], "name": k[3], "count": v} for k, v in counts.most_common(MAX_EVIDENCE_ITEMS)]
    return _finding(check_id, "WARN" if rows else "PASS", f"{sum(counts.values())} Warning event occurrence(s) correlated." if rows else "No Warning events observed in authorized namespaces.", {"warning_groups": rows})


def _network_cilium(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    if skipped := _collector_skip(bundle, "pods", check_id, "Pod"):
        return skipped
    candidates = []
    for item in _items(bundle, "pods"):
        ns, name = _meta(item)
        labels = (item.get("metadata") or {}).get("labels") or {}
        if name.startswith("cilium-") or labels.get("k8s-app") == "cilium":
            candidates.append(item)
    if not candidates:
        return _finding(check_id, "SKIP", "Cilium pods are not visible in the authorized target scope.")
    bad = [_id(x) for x in candidates if not _pod_ready(x)]
    return _finding(check_id, "FAIL" if bad else "PASS", f"{len(bad)} unhealthy Cilium pod(s)." if bad else "Visible Cilium pods are Ready.", {"unhealthy_cilium_pods": _bounded(bad), "visible_cilium_pods": len(candidates)})


def _network_hubble(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    data = bundle.get("hubble") or {}
    if data.get("error"):
        return _finding(check_id, "FAIL", "Hubble Relay health/flow collection failed.", {"collector_error": str(data.get("error"))[:500]})
    summary = data.get("summary") or {}
    return _finding(check_id, "PASS", "Hubble Relay was reachable through the trusted broker.", {"event_count": int(summary.get("event_count") or 0), "verdict_counts": dict(summary.get("verdict_counts") or {}), "policy_drop_counts": dict(summary.get("policy_drop_counts") or {}), "raw_flow_bodies_returned": False})


def _network_policy_drops(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    data = bundle.get("hubble") or {}
    if data.get("error"):
        return _finding(check_id, "SKIP", "Hubble policy-drop summary is unavailable.", {"collector_error": str(data.get("error"))[:500]})
    drops = dict((data.get("summary") or {}).get("policy_drop_counts") or {})
    total = sum(int(x or 0) for x in drops.values())
    return _finding(check_id, "WARN" if total else "PASS", f"{total} policy drop(s) observed in the bounded Hubble sample.", {"policy_drop_counts": drops, "raw_flow_bodies_returned": False})


def _network_dns(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    if skipped := _collector_skip(bundle, "pods", check_id, "Pod"):
        return skipped
    dns_pods = []
    for pod in _items(bundle, "pods"):
        ns, name = _meta(pod)
        labels = (pod.get("metadata") or {}).get("labels") or {}
        if name.startswith("coredns-") or labels.get("k8s-app") == "kube-dns" or labels.get("k8s-app") == "coredns":
            dns_pods.append(pod)
    if not dns_pods:
        return _finding(check_id, "SKIP", "CoreDNS/kube-dns pods are not visible in the authorized target scope.")
    bad = [_id(x) for x in dns_pods if not _pod_ready(x)]
    return _finding(check_id, "FAIL" if bad else "PASS", f"{len(bad)} unhealthy DNS pod(s)." if bad else "Visible cluster DNS pods are Ready.", {"unhealthy_dns_pods": _bounded(bad), "visible_dns_pods": len(dns_pods)})


def _network_ingress(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    if skipped := _collector_skip(bundle, "ingresses", check_id, "Ingress"):
        return skipped
    issues = []
    for ing in _items(bundle, "ingresses"):
        spec = ing.get("spec") or {}
        status = ing.get("status") or {}
        lb = ((status.get("loadBalancer") or {}).get("ingress") or [])
        if not spec.get("ingressClassName") and not ((ing.get("metadata") or {}).get("annotations") or {}).get("kubernetes.io/ingress.class"):
            issues.append({"ingress": _id(ing), "issue": "ingress-class-missing"})
        if not lb:
            issues.append({"ingress": _id(ing), "issue": "load-balancer-address-missing"})
    return _finding(check_id, "WARN" if issues else "PASS", f"{len(issues)} ingress configuration/status issue(s)." if issues else "Authorized Ingress resources have class/address metadata.", {"issues": _bounded(issues), "ingress_count": len(_items(bundle, "ingresses"))})


def _network_policy(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    for key, label in (("pods", "Pod"), ("networkpolicies", "NetworkPolicy")):
        if skipped := _collector_skip(bundle, key, check_id, label):
            return skipped
    namespaces_with_pods = {(_meta(x)[0]) for x in _items(bundle, "pods") if _meta(x)[0]}
    namespaces_with_policy = {(_meta(x)[0]) for x in _items(bundle, "networkpolicies") if _meta(x)[0]}
    uncovered = sorted(namespaces_with_pods - namespaces_with_policy)
    return _finding(check_id, "WARN" if uncovered else "PASS", f"{len(uncovered)} scoped namespace(s) have pods but no NetworkPolicy observed." if uncovered else "NetworkPolicy resources are present for scoped namespaces containing pods.", {"namespaces_without_policy": _bounded(uncovered), "networkpolicy_count": len(_items(bundle, "networkpolicies"))})


def _rbac_rule_dangerous(rule: dict[str, Any]) -> list[str]:
    verbs = {str(x) for x in (rule.get("verbs") or [])}
    resources = {str(x) for x in (rule.get("resources") or [])}
    issues = []
    if verbs & DANGEROUS_RBAC_VERBS:
        issues.append("dangerous-verb")
    if "*" in resources:
        issues.append("all-resources")
    if resources & DANGEROUS_RBAC_RESOURCES and ("*" in verbs or {"get", "list", "watch", "create", "update", "patch"} & verbs):
        issues.append("sensitive-resource")
    return issues


def _security_rbac(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    if skipped := _collector_skip(bundle, "roles", check_id, "Role"):
        return skipped
    findings = []
    for key in ("roles", "clusterroles"):
        for role in _items(bundle, key):
            issues = sorted({reason for rule in (role.get("rules") or []) if isinstance(rule, dict) for reason in _rbac_rule_dangerous(rule)})
            if issues:
                findings.append({"role": _id(role, include_kind=True), "issues": issues})
    err = _error(bundle, "clusterroles")
    status = "WARN" if findings or err else "PASS"
    return _finding(check_id, status, f"{len(findings)} role(s) contain broad/sensitive RBAC rules.", {"dangerous_roles": _bounded(findings), "cluster_role_scope_error": err})


def _pod_containers(pod: dict[str, Any]) -> list[dict[str, Any]]:
    spec = pod.get("spec") or {}
    out = []
    for key in ("initContainers", "containers", "ephemeralContainers"):
        out.extend(x for x in (spec.get(key) or []) if isinstance(x, dict))
    return out


def _security_privileged(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    if skipped := _collector_skip(bundle, "pods", check_id, "Pod"):
        return skipped
    hits = []
    for pod in _items(bundle, "pods"):
        for c in _pod_containers(pod):
            if (c.get("securityContext") or {}).get("privileged") is True:
                hits.append({"pod": _id(pod), "container": str(c.get("name") or "")})
    return _finding(check_id, "WARN" if hits else "PASS", f"{len(hits)} privileged container(s) observed." if hits else "No privileged containers observed in authorized pods.", {"privileged_containers": _bounded(hits)})


def _security_caps(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    if skipped := _collector_skip(bundle, "pods", check_id, "Pod"):
        return skipped
    hits = []
    for pod in _items(bundle, "pods"):
        for c in _pod_containers(pod):
            added = {str(x).upper() for x in (((c.get("securityContext") or {}).get("capabilities") or {}).get("add") or [])}
            dangerous = sorted(added & DANGEROUS_CAPABILITIES)
            if dangerous:
                hits.append({"pod": _id(pod), "container": str(c.get("name") or ""), "capabilities": dangerous})
    return _finding(check_id, "WARN" if hits else "PASS", f"{len(hits)} container(s) add dangerous Linux capabilities." if hits else "No configured dangerous capability additions observed.", {"dangerous_capabilities": _bounded(hits)})


def _security_hostpath(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    if skipped := _collector_skip(bundle, "pods", check_id, "Pod"):
        return skipped
    hits = []
    for pod in _items(bundle, "pods"):
        for volume in ((pod.get("spec") or {}).get("volumes") or []):
            if isinstance(volume, dict) and isinstance(volume.get("hostPath"), dict):
                hits.append({"pod": _id(pod), "volume": str(volume.get("name") or ""), "type": str((volume.get("hostPath") or {}).get("type") or "")})
    return _finding(check_id, "WARN" if hits else "PASS", f"{len(hits)} hostPath volume(s) observed." if hits else "No hostPath volumes observed in authorized pods.", {"hostpath_volumes": _bounded(hits)})


def _security_services(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    if skipped := _collector_skip(bundle, "services", check_id, "Service"):
        return skipped
    exposed = []
    for svc in _items(bundle, "services"):
        spec = svc.get("spec") or {}
        typ = str(spec.get("type") or "ClusterIP")
        if typ in {"NodePort", "LoadBalancer", "ExternalName"} or spec.get("externalIPs"):
            exposed.append({"service": _id(svc), "type": typ, "external_ip_count": len(spec.get("externalIPs") or [])})
    return _finding(check_id, "WARN" if exposed else "PASS", f"{len(exposed)} externally exposed service(s) observed." if exposed else "No NodePort/LoadBalancer/ExternalName/externalIP services observed.", {"exposed_services": _bounded(exposed)})


def _security_ingress_tls(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    if skipped := _collector_skip(bundle, "ingresses", check_id, "Ingress"):
        return skipped
    missing = []
    for ing in _items(bundle, "ingresses"):
        if not ((ing.get("spec") or {}).get("tls") or []):
            missing.append(_id(ing))
    return _finding(check_id, "WARN" if missing else "PASS", f"{len(missing)} Ingress resource(s) have no TLS configuration." if missing else "Authorized Ingress resources declare TLS.", {"ingress_without_tls": _bounded(missing)})


def _security_webhooks(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    if (err := _error(bundle, "webhooks")):
        return _finding(check_id, "SKIP", "Admission webhook diagnostics require cluster_read target scope.", {"collector_error": err})
    issues = []
    for cfg in _items(bundle, "webhooks"):
        for wh in (cfg.get("webhooks") or []):
            if not isinstance(wh, dict):
                continue
            local = []
            if str(wh.get("failurePolicy") or "Fail") == "Ignore":
                local.append("failure-policy-ignore")
            if not ((wh.get("clientConfig") or {}).get("caBundle")):
                local.append("ca-bundle-missing")
            if local:
                issues.append({"configuration": _id(cfg, include_kind=True), "webhook": str(wh.get("name") or ""), "issues": local})
    return _finding(check_id, "WARN" if issues else "PASS", f"{len(issues)} admission webhook issue(s) observed." if issues else "Visible admission webhook configurations pass baseline checks.", {"webhook_issues": _bounded(issues)})


def _gitops_argocd(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    if (err := _error(bundle, "argocd_applications")):
        return _finding(check_id, "SKIP", "Argo CD Application resources are unavailable or outside target scope.", {"collector_error": err})
    apps = _items(bundle, "argocd_applications")
    if not apps:
        return _finding(check_id, "SKIP", "No Argo CD Application resources observed in authorized scope.")
    bad = []
    for app in apps:
        status = app.get("status") or {}
        sync = str((status.get("sync") or {}).get("status") or "Unknown")
        health = str((status.get("health") or {}).get("status") or "Unknown")
        if sync not in {"Synced"} or health not in {"Healthy", "Progressing"}:
            bad.append({"application": _id(app), "sync": sync, "health": health})
    return _finding(check_id, "WARN" if bad else "PASS", f"{len(bad)} Argo CD Application(s) are not Synced/Healthy." if bad else "Visible Argo CD Applications are Synced and healthy/progressing.", {"applications": _bounded(bad), "application_count": len(apps)})


def _rollout(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    if skipped := _collector_skip(bundle, "workloads", check_id, "Workload"):
        return skipped
    issues = [x for x in (_workload_issue(item) for item in _items(bundle, "workloads")) if x]
    progressing = []
    for item in _items(bundle, "workloads"):
        for cond in ((item.get("status") or {}).get("conditions") or []):
            if not isinstance(cond, dict):
                continue
            if cond.get("type") in {"Progressing", "Available"} and str(cond.get("status")).lower() == "false":
                progressing.append({"workload": _id(item, include_kind=True), "condition": str(cond.get("type")), "reason": str(cond.get("reason") or "")})
    combined = _bounded(issues + progressing)
    return _finding(check_id, "FAIL" if combined else "PASS", f"{len(combined)} rollout health issue(s) observed." if combined else "Authorized workload rollouts satisfy readiness/condition checks.", {"rollout_issues": combined})


def _certificates(bundle: dict[str, Any], check_id: str, observed_at: int) -> dict[str, Any]:
    if (err := _error(bundle, "certificates")):
        return _finding(check_id, "SKIP", "cert-manager Certificate resources are unavailable or outside target scope.", {"collector_error": err})
    items = _items(bundle, "certificates")
    if not items:
        return _finding(check_id, "SKIP", "No cert-manager Certificate resources observed in authorized scope.")
    issues = []
    now = datetime.fromtimestamp(observed_at, tz=timezone.utc)
    for cert in items:
        status = cert.get("status") or {}
        not_after = str(status.get("notAfter") or "")
        ready = False
        for cond in status.get("conditions") or []:
            if isinstance(cond, dict) and cond.get("type") == "Ready" and str(cond.get("status")).lower() == "true":
                ready = True
        days = None
        if not_after:
            try:
                expiry = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                days = int((expiry - now).total_seconds() // 86400)
            except ValueError:
                pass
        if not ready or days is None or days < 30:
            issues.append({"certificate": _id(cert), "ready": ready, "days_remaining": days})
    return _finding(check_id, "WARN" if issues else "PASS", f"{len(issues)} certificate readiness/expiry issue(s)." if issues else "Visible cert-manager Certificates are Ready with at least 30 days remaining.", {"certificate_issues": _bounded(issues), "certificate_count": len(items)})


def _backups(bundle: dict[str, Any], check_id: str) -> dict[str, Any]:
    if (err := _error(bundle, "velero_backups")):
        return _finding(check_id, "SKIP", "Velero Backup resources are unavailable or outside target scope.", {"collector_error": err})
    items = _items(bundle, "velero_backups")
    if not items:
        return _finding(check_id, "SKIP", "No Velero Backup resources observed in authorized scope.")
    bad = []
    for backup in items:
        phase = str((backup.get("status") or {}).get("phase") or "Unknown")
        if phase not in {"Completed", "InProgress"}:
            bad.append({"backup": _id(backup), "phase": phase})
    return _finding(check_id, "WARN" if bad else "PASS", f"{len(bad)} Velero Backup(s) have non-success phases." if bad else "Visible Velero backups are Completed/InProgress.", {"backup_issues": _bounded(bad), "backup_count": len(items)})


def evaluate(*, bundle: dict[str, Any], requested_checks: list[str], observed_at: int) -> dict[str, Any]:
    requested = list(dict.fromkeys(requested_checks or DEFAULT_CHECK_IDS))
    unknown = sorted(set(requested) - set(CHECK_IDS))
    if unknown:
        raise ValueError(f"unsupported diagnostic checks: {', '.join(unknown)}")

    handlers = {
        "nodes.health": _nodes,
        "pods.health": _pods,
        "workloads.health": _workloads,
        "pods.oom": _oom,
        "resources.cpu-memory": _metrics,
        "storage.health": _storage,
        "events.correlation": _events,
        "network.cilium": _network_cilium,
        "network.hubble": _network_hubble,
        "network.dns": _network_dns,
        "network.ingress": _network_ingress,
        "network.networkpolicy": _network_policy,
        "security.rbac": _security_rbac,
        "security.privileged": _security_privileged,
        "security.capabilities": _security_caps,
        "security.hostpath": _security_hostpath,
        "security.exposed-services": _security_services,
        "security.ingress-tls": _security_ingress_tls,
        "security.webhooks": _security_webhooks,
        "gitops.argocd": _gitops_argocd,
        "rollout.health": _rollout,
    }

    results: list[dict[str, Any]] = []
    for original in requested:
        canonical = ALIASES.get(original, original)
        if original == "network.policy-drops":
            result = _network_policy_drops(bundle, original)
        elif original == "certificates.expiry":
            result = _certificates(bundle, original, observed_at)
        elif original == "backup.recency":
            result = _backups(bundle, original)
        else:
            result = handlers[canonical](bundle, original)
        results.append(result)

    counts = Counter(x["status"] for x in results)
    overall = "FAIL" if counts["FAIL"] else ("WARN" if counts["WARN"] else ("SKIP" if counts["PASS"] == 0 else "PASS"))
    return {
        "provider": "hermes-native-kubernetes-diagnostics",
        "observed_at": observed_at,
        "overall_status": overall,
        "checks": results,
        "summary": {status: int(counts[status]) for status in ("PASS", "WARN", "FAIL", "SKIP")},
        "secret_data_requested": False,
        "mutation_commands_executed": False,
    }
