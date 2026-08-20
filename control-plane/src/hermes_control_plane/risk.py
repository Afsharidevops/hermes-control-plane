from __future__ import annotations

from typing import Literal

Risk = Literal["READ", "LOW", "HIGH", "CRITICAL"]

_READ_PREFIXES = (
    "get.", "list.", "read.", "describe.", "discover.", "health.", "logs.", "status.", "inspect.",
)
_CRITICAL_MARKERS = (
    "cluster-admin", "cluster_admin", "rbac.", "namespace.delete", "secret.read", "secret.export",
    "docker.privileged", "host.mount", "host_root", "force-push", "force_push",
    "restore", "disaster-recovery", "disaster_recovery",
)
_HIGH_MARKERS = (
    ".delete", ".remove", ".apply", ".install", ".uninstall", ".upgrade", ".rollback", ".scale", ".restart",
    ".deploy", ".merge", ".push", "compose.down", "swarm.", "ingress.",
)


def classify(operation: str) -> Risk:
    op = operation.strip().lower()
    if op.startswith(_READ_PREFIXES):
        return "READ"
    if any(marker in op for marker in _CRITICAL_MARKERS):
        return "CRITICAL"
    if any(marker in op for marker in _HIGH_MARKERS):
        return "HIGH"
    return "LOW"


def approval_required(risk: Risk) -> bool:
    return risk in {"HIGH", "CRITICAL"}
