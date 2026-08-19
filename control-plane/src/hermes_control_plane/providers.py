from __future__ import annotations

from typing import Any

LIFECYCLE = ["discover", "validate", "plan", "apply", "verify", "upgrade", "rollback", "destroy"]

PROVIDERS: dict[str, dict[str, Any]] = {
    "ssh": {
        "kind": "host-access",
        "lifecycle": ["discover", "validate", "plan", "verify"],
        "execution": "agent-or-broker",
        "credential_class": "ssh",
        "mutation_policy": "changeset-only",
        "notes": ["pinned host fingerprint required", "fixed typed preflight only", "no unrestricted shell endpoint"],
    },
    "kubespray": {
        "kind": "cluster-bootstrap",
        "lifecycle": LIFECYCLE,
        "execution": "agent-or-provider-worker",
        "credential_class": "ssh",
        "mutation_policy": "changeset-only",
        "status": "dev3-production-path",
        "plan_contract": "KubesprayExecutionSpec",
        "provider_version_pin": "required",
        "network_plugin": "cilium",
    },
    "k3s": {
        "kind": "cluster-bootstrap",
        "lifecycle": LIFECYCLE,
        "execution": "agent-or-provider-worker",
        "credential_class": "ssh",
        "mutation_policy": "changeset-only",
        "status": "dev3-lab-edge-path",
        "plan_contract": "K3sExecutionSpec",
        "provider_version_pin": "required",
        "network_plugin": "cilium",
    },
    "rke2": {
        "kind": "cluster-bootstrap",
        "lifecycle": LIFECYCLE,
        "execution": "agent-or-provider-worker",
        "credential_class": "ssh",
        "mutation_policy": "changeset-only",
        "status": "dev3-hardened-path",
        "plan_contract": "RKE2ExecutionSpec",
        "provider_version_pin": "required",
        "network_plugin": "cilium",
        "hardening_required": True,
    },
    "radar": {
        "kind": "kubernetes-intelligence",
        "lifecycle": ["discover", "validate", "plan", "apply", "verify", "upgrade", "rollback", "destroy"],
        "execution": "kubernetes-broker",
        "credential_class": "kubeconfig",
        "mutation_policy": "changeset-only",
        "status": "first-class-provider-foundation",
        "dev3_status": "first-class-provider",
        "ui_contract": "hermes-native-radar-inspired",
        "governance_bypass": False,
    },
    "hubble": {
        "kind": "network-intelligence",
        "lifecycle": ["discover", "validate", "plan", "apply", "verify", "upgrade", "rollback", "destroy"],
        "execution": "kubernetes-broker",
        "credential_class": "kubeconfig",
        "mutation_policy": "changeset-only",
        "status": "first-class-provider-foundation",
        "dev3_status": "first-class-provider",
        "authorization": "required",
        "redaction": "required-before-ai-ui",
        "aggregation": "required-before-ai-ui",
        "governance_bypass": False,
    },
}


def provider_descriptor(provider_id: str) -> dict[str, Any] | None:
    spec = PROVIDERS.get(provider_id)
    return {"id": provider_id, **spec} if spec else None
