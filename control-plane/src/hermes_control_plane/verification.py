from __future__ import annotations

from typing import Any

from .operations import VERIFICATION_CHECKS

STATUS_ORDER = {"SKIP": 0, "PASS": 1, "WARN": 2, "FAIL": 3}

DIAGNOSTIC_MAP: dict[str, tuple[str, ...]] = {
    "networking": ("network.cilium", "network.hubble", "network.dns", "network.ingress", "network.networkpolicy"),
    "api-server": (),
    "nodes": ("nodes.health",),
    "cilium": ("network.cilium",),
    "hubble": ("network.hubble",),
    "dns": ("network.dns",),
    "storage": ("storage.health",),
    "ingress-tls": ("network.ingress", "security.ingress-tls", "certificates.expiry"),
    "gitops": ("gitops.argocd",),
    "observability": ("resources.cpu-memory",),
    "baseline-security": (
        "security.rbac",
        "security.privileged",
        "security.capabilities",
        "security.hostpath",
        "security.exposed-services",
        "security.ingress-tls",
        "security.webhooks",
    ),
}


def selected_checks(requested: list[str]) -> list[str]:
    selected = list(dict.fromkeys(requested or VERIFICATION_CHECKS))
    unknown = sorted(set(selected) - set(VERIFICATION_CHECKS))
    if unknown:
        raise ValueError(f"unsupported verification checks: {', '.join(unknown)}")
    return selected


def diagnostic_check_ids(selected: list[str]) -> list[str]:
    ids: list[str] = []
    for check_id in selected:
        for diagnostic_id in DIAGNOSTIC_MAP.get(check_id, ()):
            if diagnostic_id not in ids:
                ids.append(diagnostic_id)
    return ids


def _aggregate(check_id: str, findings: list[dict[str, Any]], *, label: str) -> dict[str, Any]:
    if not findings:
        return {"id": check_id, "status": "SKIP", "summary": f"{label} has no active collector result.", "evidence": {"collector": "not-available"}}
    worst = max(findings, key=lambda item: STATUS_ORDER.get(str(item.get("status")), 3))
    status = str(worst.get("status") or "FAIL")
    summaries = [str(item.get("summary") or "")[:300] for item in findings]
    evidence = {
        "source": "hermes-native-kubernetes-diagnostics",
        "diagnostic_checks": [
            {
                "id": str(item.get("id") or ""),
                "status": str(item.get("status") or "FAIL"),
                "summary": str(item.get("summary") or "")[:500],
                "evidence": item.get("evidence") or {},
            }
            for item in findings
        ],
    }
    return {"id": check_id, "status": status, "summary": f"{label}: " + " | ".join(summaries)[:900], "evidence": evidence}


def from_diagnostics(result: dict[str, Any], selected: list[str]) -> list[dict[str, Any]]:
    by_id = {str(item.get("id")): item for item in (result.get("checks") or []) if isinstance(item, dict)}
    checks: list[dict[str, Any]] = []
    for check_id in selected:
        if check_id == "api-server":
            checks.append({
                "id": "api-server",
                "status": "PASS",
                "summary": "Trusted Kubernetes Broker completed an authenticated live Kubernetes API diagnostics collection.",
                "evidence": {"source": "kubernetes-broker", "observed_at": result.get("observed_at"), "mutation_commands_executed": False},
            })
            continue
        mapped = DIAGNOSTIC_MAP.get(check_id)
        if mapped is not None:
            findings = [by_id[item] for item in mapped if item in by_id]
            label = {
                "networking": "Kubernetes network verification",
                "nodes": "Node readiness verification",
                "cilium": "Cilium verification",
                "hubble": "Hubble verification",
                "dns": "DNS verification",
                "storage": "Storage verification",
                "ingress-tls": "Ingress/TLS verification",
                "gitops": "GitOps verification",
                "observability": "Observability verification",
                "baseline-security": "Security baseline verification",
            }.get(check_id, check_id)
            aggregated = _aggregate(check_id, findings, label=label)
            if check_id == "observability" and aggregated["status"] == "PASS":
                aggregated["status"] = "WARN"
                aggregated["summary"] += " Kubernetes Metrics API is active; Prometheus-specific probing is not configured in this target path."
                aggregated["evidence"]["prometheus_probe"] = "not-configured"
            checks.append(aggregated)
            continue
        checks.append({
            "id": check_id,
            "status": "SKIP",
            "summary": {
                "hosts": "Active host/SSH verification requires a trusted host agent/provider runtime and is not inferred from stored preflight state.",
                "etcd": "Direct etcd quorum verification is not exposed by the current constrained Kubernetes Broker collector.",
                "radar": "Radar verification requires a configured Radar integration and is evaluated by the Control Plane.",
                "hermes-agent": "Hermes Agent verification requires an explicit active agent target and is not inferred from enrollment records.",
            }.get(check_id, "No active verifier is available for this check."),
            "evidence": {"collector": "not-available"},
        })
    return checks


def replace_check(checks: list[dict[str, Any]], replacement: dict[str, Any]) -> None:
    for idx, item in enumerate(checks):
        if item.get("id") == replacement.get("id"):
            checks[idx] = replacement
            return
    checks.append(replacement)


def overall_status(checks: list[dict[str, Any]]) -> str:
    statuses = [str(item.get("status") or "FAIL") for item in checks]
    if not statuses or all(status == "SKIP" for status in statuses):
        return "SKIP"
    if "FAIL" in statuses:
        return "FAIL"
    if "WARN" in statuses:
        return "WARN"
    if "PASS" in statuses:
        return "PASS"
    return "SKIP"
