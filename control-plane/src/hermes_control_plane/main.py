from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import re
import json
import os
import secrets
import time
import uuid
from contextlib import asynccontextmanager, closing
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse

from . import db
from .canonical import canonical_json, sha256_hex
from . import kubernetes as kubernetes_broker
from . import provider_worker
from . import preflight as host_preflight
from . import cluster_factory
from . import operations
from . import operator_center
from . import verification as unified_verification
from . import artifact_mirror
from . import radar as radar_provider
from .providers import PROVIDERS, provider_descriptor
from .tickets import issue_ticket, verify_ticket
from .models import (
    AgentEnroll,
    AgentEnrollmentTokenCreate,
    AgentHeartbeat,
    AgentRevoke,
    AgentTaskClaim,
    AgentTaskCreate,
    AgentTaskResult,
    ApplicationCreate,
    ApplicationUpdate,
    ApprovalDecision,
    ChangeSetCreate,
    CredentialRefCreate,
    CredentialRefSync,
    CredentialRefUpdate,
    EnvironmentCreate,
    EnvironmentUpdate,
    ExecuteDecision,
    IntegrationCreate,
    IntegrationUpdate,
    PreviewCreate,
    PolicyGenerationBump,
    RejectDecision,
    RollbackPlanCreate,
    TargetCreate,
    TargetUpdate,
    ServerCreate,
    ServerUpdate,
    ServerPreflightResult,
    BootstrapPlanCreate,
    ProviderJobTransition,
    ProviderJobRetry,
    ClusterBlueprintCreate,
    OperationalProfileBlueprintCreate,
    ClusterBlueprintArtifactDependenciesUpdate,
    ClusterProfileCreate,
    ClusterCreate,
    NodeRoleCreate,
    ProvisioningRunCreate,
    AddonPlanCreate,
    UpgradePlanCreate,
    BackupPlanCreate,
    RadarSnapshotCreate,
    RadarIntelligenceQuery,
    HubbleFlowSummaryCreate,
    HubbleLiveQuery,
    KubernetesDiagnosticsQuery,
    KubernetesDiagnosticsBrokerResult,
    UnifiedVerificationQuery,
    InfrastructureProviderCreate,
    InfrastructureProviderHealth,
    OperationsIntentPlanCreate,
    ArtifactMirrorItemCreate,
    VerificationResultCreate,
    OperationJobTransition,
    OperationJobExecute,
)
from .risk import approval_required, classify

VERSION = "0.5.11-dev.5"
STATIC_DIR = Path(__file__).resolve().parent / "static"
TERMINAL_CHANGESET_STATES = {
    "REJECTED", "CANCELLED", "EXPIRED", "EXECUTED", "FAILED",
    "POLICY_DENIED", "PREVIEW_FAILED", "STALE_POLICY",
}
INFRA_MUTATION_ADAPTERS = {"kubernetes", "helm", "ssh", "bootstrap", "radar", "hubble", "provider", "fleet", "cloud", "bare-metal", "network", "artifact"}
BOT_SOURCE_CHANNELS = {"ui", "telegram", "hermes-bot", "api"}

ADAPTER_CAPABILITIES: dict[str, dict[str, Any]] = {
    "kubernetes.discover": {"adapter": "kubernetes", "mode": "read", "default_risk": "READ", "reversible": False, "credential_class": "kubeconfig", "connection_modes": ["direct", "agent"], "approval": "none", "target_restrictions": ["namespace allowlist", "no Secret value reads"]},
    "kubernetes.diagnostics": {"adapter": "kubernetes", "mode": "read", "default_risk": "READ", "reversible": False, "credential_class": "kubeconfig", "connection_modes": ["direct", "agent"], "approval": "none", "target_restrictions": ["fixed read-only collectors", "namespace/cluster scope", "no Secret/env/log bodies", "bounded typed findings"]},
    "cluster.verify": {"adapter": "kubernetes", "mode": "read", "default_risk": "READ", "reversible": False, "credential_class": "kubeconfig", "connection_modes": ["direct", "provider"], "approval": "none", "target_restrictions": ["active typed probes only", "bounded redacted evidence", "no mutation commands", "unsupported provider probes report SKIP"]},
    "kubernetes.apply": {"adapter": "kubernetes", "mode": "write", "default_risk": "HIGH", "reversible": True, "credential_class": "kubeconfig", "connection_modes": ["direct", "agent"], "approval": "policy", "target_restrictions": ["namespace/resource allowlists", "RBAC escalation denied by default"]},
    "helm.upgrade": {"adapter": "helm", "mode": "write", "default_risk": "HIGH", "reversible": True, "credential_class": "kubeconfig", "connection_modes": ["direct", "agent"], "approval": "policy", "target_restrictions": ["namespace allowlist"]},
    "docker.read": {"adapter": "docker", "mode": "read", "default_risk": "READ", "reversible": False, "credential_class": "docker-socket-local", "connection_modes": ["agent"], "approval": "none", "target_restrictions": ["socket broker/agent only"]},
    "docker.restart": {"adapter": "docker", "mode": "write", "default_risk": "LOW", "reversible": True, "credential_class": "docker-socket-local", "connection_modes": ["agent"], "approval": "policy", "target_restrictions": ["container allowlist"]},
    "docker.deploy": {"adapter": "docker", "mode": "write", "default_risk": "HIGH", "reversible": True, "credential_class": "docker-socket-local", "connection_modes": ["agent"], "approval": "policy", "target_restrictions": ["structured deployment only", "privileged/root mounts denied by default"]},
    "compose.apply": {"adapter": "compose", "mode": "write", "default_risk": "HIGH", "reversible": True, "credential_class": "docker-socket-local", "connection_modes": ["agent"], "approval": "policy", "target_restrictions": ["validated compose project"]},
    "swarm.deploy": {"adapter": "swarm", "mode": "write", "default_risk": "HIGH", "reversible": True, "credential_class": "docker-socket-local", "connection_modes": ["agent"], "approval": "policy", "target_restrictions": ["stack/service allowlist"]},
    "ssh.profile.verify": {"adapter": "ssh", "mode": "read", "default_risk": "READ", "reversible": False, "credential_class": "ssh", "connection_modes": ["direct", "agent"], "approval": "none", "target_restrictions": ["host fingerprint required"]},
    "ssh.preflight": {"adapter": "ssh", "mode": "read", "default_risk": "READ", "reversible": False, "credential_class": "ssh", "connection_modes": ["direct", "agent"], "approval": "none", "target_restrictions": ["host fingerprint required", "fixed read-only checks only"]},
    "bootstrap.apply": {"adapter": "bootstrap", "mode": "write", "default_risk": "HIGH", "reversible": True, "credential_class": "ssh", "connection_modes": ["agent"], "approval": "policy", "target_restrictions": ["typed provider plan only", "approved ChangeSet required", "no generated shell"]},
    "radar.discover": {"adapter": "radar", "mode": "read", "default_risk": "READ", "reversible": False, "credential_class": "kubeconfig", "connection_modes": ["direct", "agent"], "approval": "none", "target_restrictions": ["read intelligence only"]},
    "radar.apply": {"adapter": "radar", "mode": "write", "default_risk": "HIGH", "reversible": True, "credential_class": "kubeconfig", "connection_modes": ["direct", "agent"], "approval": "policy", "target_restrictions": ["must execute through Hermes ChangeSet"]},
    "hubble.flows": {"adapter": "hubble", "mode": "read", "default_risk": "READ", "reversible": False, "credential_class": "kubeconfig", "connection_modes": ["direct", "agent"], "approval": "none", "target_restrictions": ["authorization, redaction, aggregation before AI/UI"]},
    "cluster.provision.apply": {"adapter": "bootstrap", "mode": "write", "default_risk": "HIGH", "reversible": False, "credential_class": "ssh", "connection_modes": ["agent"], "approval": "policy", "target_restrictions": ["ClusterBlueprint/Profile/NodeRole typed plan", "all nodes PASS preflight", "exact ChangeSet hash"]},
    "cluster.addons.apply": {"adapter": "provider", "mode": "write", "default_risk": "HIGH", "reversible": True, "credential_class": "kubeconfig", "connection_modes": ["direct", "agent"], "approval": "policy", "target_restrictions": ["typed AddonPlan", "explicit version pins", "exact ChangeSet hash"]},
    "cluster.upgrade": {"adapter": "bootstrap", "mode": "write", "default_risk": "HIGH", "reversible": False, "credential_class": "ssh", "connection_modes": ["agent"], "approval": "policy", "target_restrictions": ["typed UpgradePlan", "backup-first", "provider compatibility gate"]},
    "cluster.backup.apply": {"adapter": "provider", "mode": "write", "default_risk": "HIGH", "reversible": True, "credential_class": "kubeconfig", "connection_modes": ["direct", "agent"], "approval": "policy", "target_restrictions": ["typed BackupPlan", "restore verification required"]},
    "ssh.runbook.execute": {"adapter": "ssh", "mode": "write", "default_risk": "HIGH", "reversible": False, "credential_class": "ssh", "connection_modes": ["agent"], "approval": "policy", "target_restrictions": ["structured runbook only", "no unrestricted shell endpoint"]},
    "github.gitops": {"adapter": "github", "mode": "write", "default_risk": "HIGH", "reversible": True, "credential_class": "token", "connection_modes": ["direct"], "approval": "policy", "target_restrictions": ["controlled files", "protected branch policy"]},
    "gitlab.gitops": {"adapter": "gitlab", "mode": "write", "default_risk": "HIGH", "reversible": True, "credential_class": "token", "connection_modes": ["direct"], "approval": "policy", "target_restrictions": ["controlled files", "protected branch policy"]},
    "fleet.apply": {"adapter": "fleet", "mode": "write", "default_risk": "HIGH", "reversible": False, "credential_class": "indirect", "connection_modes": ["agent", "provider"], "approval": "policy", "target_restrictions": ["exact fleet target snapshot", "reject target drift", "per-cluster audit"]},
    "cloud.apply": {"adapter": "cloud", "mode": "write", "default_risk": "HIGH", "reversible": True, "credential_class": "cloud", "connection_modes": ["provider"], "approval": "policy", "target_restrictions": ["typed provider contract", "credential-service delivery only", "exact ChangeSet hash"]},
    "bare-metal.apply": {"adapter": "bare-metal", "mode": "write", "default_risk": "HIGH", "reversible": False, "credential_class": "bmc", "connection_modes": ["provider"], "approval": "policy", "target_restrictions": ["typed Redfish/IPMI/PXE contract", "no generated shell", "exact ChangeSet hash"]},
    "network.apply": {"adapter": "network", "mode": "write", "default_risk": "HIGH", "reversible": True, "credential_class": "switch", "connection_modes": ["provider"], "approval": "policy", "target_restrictions": ["typed switch intent", "no arbitrary CLI", "exact ChangeSet hash"]},
    "artifact.mirror.apply": {"adapter": "artifact", "mode": "write", "default_risk": "HIGH", "reversible": True, "credential_class": "registry-or-repository", "connection_modes": ["provider"], "approval": "policy", "target_restrictions": ["version and sha256 digest pinned", "source/destination digest verification", "trusted file/allowlisted-HTTPS to file plus allowlisted OCI-image registry-to-registry runtime; other repository protocols remain explicit contract-only"]},
}


def _is_infra_mutation(adapter: str, operation: str) -> bool:
    """Keep read-only Kubernetes/Helm inspection available to admin/UI, but mutations bot-only."""
    return adapter in INFRA_MUTATION_ADAPTERS and classify(operation) != "READ"


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
    yield


app = FastAPI(
    title="Hermes Control Plane API",
    version=VERSION,
    description="Hermes Control Plane 0.5.11-dev.5 development API",
    lifespan=lifespan,
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _admin_token() -> str:
    return os.getenv("HERMES_CONTROL_ADMIN_TOKEN", "")


def _bot_token() -> str:
    return os.getenv("HERMES_BOT_SERVICE_TOKEN", "")


def _approval_bot_token() -> str:
    return os.getenv("HERMES_APPROVAL_BOT_TOKEN", "")


def _credential_service_token() -> str:
    return os.getenv("HERMES_CREDENTIAL_SERVICE_TOKEN", "")


def _approval_hmac_key() -> bytes:
    key = os.getenv("HERMES_APPROVAL_HMAC_KEY", "").encode("utf-8")
    if len(key) < 32:
        raise HTTPException(status_code=503, detail="HERMES_APPROVAL_HMAC_KEY must be configured with at least 32 bytes")
    return key


def _agent_task_hmac_key() -> bytes:
    key = os.getenv("HERMES_AGENT_TASK_HMAC_KEY", "").encode("utf-8")
    if len(key) < 32:
        raise HTTPException(status_code=503, detail="HERMES_AGENT_TASK_HMAC_KEY must be configured with at least 32 bytes")
    return key

def _agent_task_signature(envelope: dict[str, Any]) -> str:
    return hmac.new(_agent_task_hmac_key(), canonical_json(envelope).encode("utf-8"), hashlib.sha256).hexdigest()


def _hash_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _approval_mac_payload(record: dict[str, Any]) -> bytes:
    signed = {
        "id": record["id"],
        "changeset_id": record["changeset_id"],
        "plan_hash": record["plan_hash"],
        "approver": record["approver"],
        "issued_at": int(record["issued_at"]),
        "expires_at": int(record["expires_at"]),
        "policy_generation": int(record["policy_generation"]),
        "policy_id": record["policy_id"],
        "policy_version": int(record["policy_version"]),
        "nonce": record["nonce"],
    }
    return canonical_json(signed).encode("utf-8")


def _approval_mac(record: dict[str, Any]) -> str:
    return hmac.new(_approval_hmac_key(), _approval_mac_payload(record), hashlib.sha256).hexdigest()


def _approval_is_valid(row: Any, *, changeset: Any, now: int) -> bool:
    record = dict(row)
    if record.get("status") != "APPROVED" or record.get("consumed_at") is not None:
        return False
    if int(record.get("expires_at") or 0) < now:
        return False
    if int(record.get("policy_generation") or 0) != int(changeset["policy_generation"]):
        return False
    if record.get("plan_hash") != changeset["plan_hash"] or not record.get("nonce") or not record.get("mac"):
        return False
    try:
        expected = _approval_mac(record)
    except (KeyError, TypeError, ValueError):
        return False
    return hmac.compare_digest(str(record["mac"]), expected)


def _require_token(authorization: str | None, token: str, label: str) -> None:
    if not token:
        raise HTTPException(status_code=503, detail=f"{label} is not configured")
    if authorization != f"Bearer {token}":
        raise HTTPException(status_code=401, detail=f"invalid {label.lower()}")


def _require_admin(authorization: str | None) -> None:
    _require_token(authorization, _admin_token(), "HERMES_CONTROL_ADMIN_TOKEN")


def _require_bot(authorization: str | None) -> None:
    if authorization == f"Bearer {_admin_token()}":
        raise HTTPException(status_code=403, detail="Kubernetes and Helm mutation is bot-only")
    _require_token(authorization, _bot_token(), "HERMES_BOT_SERVICE_TOKEN")


def _require_approval_bot(authorization: str | None) -> None:
    if authorization in {f"Bearer {_admin_token()}", f"Bearer {_bot_token()}"}:
        raise HTTPException(status_code=403, detail="approval is restricted to the separate Approval Bot identity")
    _require_token(authorization, _approval_bot_token(), "HERMES_APPROVAL_BOT_TOKEN")


def _require_credential_service(authorization: str | None) -> None:
    if authorization in {f"Bearer {_admin_token()}", f"Bearer {_bot_token()}", f"Bearer {_approval_bot_token()}"}:
        raise HTTPException(status_code=403, detail="credential metadata sync is restricted to the separate Credential Service identity")
    _require_token(authorization, _credential_service_token(), "HERMES_CREDENTIAL_SERVICE_TOKEN")


def _require_bot_origin(source_channel: str) -> None:
    if source_channel not in BOT_SOURCE_CHANNELS:
        raise HTTPException(
            status_code=403,
            detail="Kubernetes and Helm mutation plans may only originate from Hermes Bot",
        )


def _require_infra_actor(row: Any, authorization: str | None) -> None:
    if _is_infra_mutation(row["adapter"], row["operation"]):
        _require_bot(authorization)
    else:
        _require_admin(authorization)


def _row_json(row: Any, json_fields: dict[str, str]) -> dict[str, Any]:
    item = dict(row)
    for source, dest in json_fields.items():
        raw = item.pop(source, None)
        item[dest] = json.loads(raw or "{}")
    return item


def _get_environment(conn, environment_id: str):
    row = conn.execute("SELECT * FROM environments WHERE id=?", (environment_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="environment not found")
    return row


def _get_credential_ref(conn, credential_ref: str | None):
    if not credential_ref:
        return None
    row = conn.execute("SELECT * FROM credential_refs WHERE id=?", (credential_ref,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="credential reference not found")
    if row["status"] == "revoked":
        raise HTTPException(status_code=409, detail="credential reference is revoked")
    return row


def _integration_dict(row: Any) -> dict[str, Any]:
    item = _row_json(row, {"labels_json": "labels", "allowed_scope_json": "allowed_scope"})
    item.pop("environment", None)  # legacy alpha.1 compatibility column
    return item


def _target_dict(row: Any) -> dict[str, Any]:
    return _row_json(row, {"scope_json": "scope", "labels_json": "labels"})


def _server_dict(row: Any) -> dict[str, Any]:
    item = _row_json(row, {"labels_json": "labels", "inventory_json": "inventory"})
    raw = item.pop("preflight_json", None)
    item["preflight"] = json.loads(raw or "null")
    return item


def _validated_ip(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"{field} must be a valid IPv4 or IPv6 address") from exc


def _validate_host_fingerprint(value: str) -> str:
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{20,}={0,2}", value):
        raise HTTPException(status_code=422, detail="host_fingerprint must be an OpenSSH SHA256 fingerprint")
    return value


def _get_server(conn, server_id: str):
    row = conn.execute("SELECT * FROM servers WHERE id=?", (server_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="server not found")
    return row


def _assert_server_ips_unique(conn, management_ip: str, provisioning_ip: str | None, bmc_ip: str | None, *, exclude_id: str | None = None) -> None:
    values = [value for value in (management_ip, provisioning_ip, bmc_ip) if value]
    if len(values) != len(set(values)):
        raise HTTPException(status_code=409, detail="server management/provisioning/BMC IPs must be distinct")
    for value in values:
        row = conn.execute(
            "SELECT id FROM servers WHERE (management_ip=? OR provisioning_ip=? OR bmc_ip=?) AND (? IS NULL OR id<>?) LIMIT 1",
            (value, value, value, exclude_id, exclude_id),
        ).fetchone()
        if row:
            raise HTTPException(status_code=409, detail=f"server IP {value} is already registered")


def _validate_server_credentials(conn, credential_ref: str, bmc_credential_ref: str | None) -> None:
    ssh = _get_credential_ref(conn, credential_ref)
    if ssh["kind"] not in {"ssh-key", "ssh-password"}:
        raise HTTPException(status_code=422, detail="server credential_ref must reference an SSH credential")
    if ssh["status"] != "configured":
        raise HTTPException(status_code=409, detail="server SSH credential is not active/configured")
    if bmc_credential_ref:
        bmc = _get_credential_ref(conn, bmc_credential_ref)
        if bmc["kind"] not in {"ssh-password", "token", "generic"}:
            raise HTTPException(status_code=422, detail="bmc_credential_ref has an unsupported credential kind")
        if bmc["status"] != "configured":
            raise HTTPException(status_code=409, detail="server BMC credential is not active/configured")


def _server_snapshot(conn, server_id: str) -> dict[str, Any]:
    row = _get_server(conn, server_id)
    server = _server_dict(row)
    raw_labels = server.get("labels") if isinstance(server.get("labels"), dict) else {}
    provisioning_labels = {
        key: str(raw_labels[key])
        for key in ("provisioning_mac", "provisioning_nic", "boot_provider_id")
        if raw_labels.get(key) is not None
    }
    snapshot = {
        "entity_type": "server",
        "id": server["id"],
        "hostname": server["hostname"],
        "environment_id": server["environment_id"],
        "management_ip": server["management_ip"],
        "provisioning_ip": server["provisioning_ip"],
        "ssh_port": server["ssh_port"],
        "ssh_user": server["ssh_user"],
        "host_fingerprint": server["host_fingerprint"],
        "connection_mode": server["connection_mode"],
        "credential_ref": server["credential_ref"],
        "status": server["status"],
        "credential_snapshot": _credential_snapshot(conn, server["credential_ref"]),
        "preflight_status": server["preflight_status"],
        "architecture": server.get("architecture"),
        "site": server.get("site"),
        "rack": server.get("rack"),
        "zone": server.get("zone"),
        "labels": provisioning_labels,
    }
    snapshot["snapshot_hash"] = sha256_hex(snapshot)
    return snapshot


def _blueprint_dict(row: Any) -> dict[str, Any]:
    item = _row_json(row, {"topology_json": "topology", "labels_json": "labels"})
    item["addon_defaults"] = json.loads(item.pop("addon_defaults_json") or "[]")
    item["addon_versions"] = json.loads(item.pop("addon_versions_json") or "{}")
    item["artifact_dependencies"] = json.loads(item.pop("artifact_dependencies_json") or "[]")
    item["hubble_enabled"] = bool(item["hubble_enabled"])
    item["radar_enabled"] = bool(item["radar_enabled"])
    return item


def _profile_dict(row: Any) -> dict[str, Any]:
    item = _row_json(row, {"overrides_json": "overrides", "labels_json": "labels"})
    item["server_ids"] = json.loads(item.pop("server_ids_json") or "[]")
    return item


def _cluster_dict(row: Any) -> dict[str, Any]:
    return _row_json(row, {"labels_json": "labels"})


def _node_role_dict(row: Any) -> dict[str, Any]:
    item = _row_json(row, {"configuration_json": "configuration"})
    item["server_ids"] = json.loads(item.pop("server_ids_json") or "[]")
    return item


def _plan_resource_dict(row: Any) -> dict[str, Any]:
    item = dict(row)
    item["plan"] = json.loads(item.pop("plan_json") or "{}")
    return item


def _provisioning_run_dict(row: Any) -> dict[str, Any]:
    item = dict(row)
    item["provider_job_ids"] = json.loads(item.pop("provider_job_ids_json") or "[]")
    item["plan"] = json.loads(item.pop("plan_json") or "{}")
    item["result"] = json.loads(item.pop("result_json") or "null")
    return item


def _infrastructure_provider_dict(row: Any) -> dict[str, Any]:
    item = dict(row)
    item["capabilities"] = json.loads(item.pop("capabilities_json") or "{}")
    item["labels"] = json.loads(item.pop("labels_json") or "{}")
    return item


def _artifact_mirror_item_dict(row: Any) -> dict[str, Any]:
    item = dict(row)
    item["labels"] = json.loads(item.pop("labels_json") or "{}")
    item["verification"] = json.loads(item.pop("verification_json") or "null")
    return item


def _operation_plan_dict(row: Any) -> dict[str, Any]:
    item = dict(row)
    item["plan"] = json.loads(item.pop("plan_json") or "{}")
    return item


def _operation_job_dict(row: Any) -> dict[str, Any]:
    item = dict(row)
    item["request"] = json.loads(item.pop("request_json") or "{}")
    item["result"] = json.loads(item.pop("result_json") or "null")
    return item


def _verification_result_dict(row: Any) -> dict[str, Any]:
    item = dict(row)
    item["checks"] = json.loads(item.pop("checks_json") or "[]")
    item["evidence"] = json.loads(item.pop("evidence_json") or "{}")
    return item


def _get_infrastructure_provider(conn, provider_id: str):
    row = conn.execute("SELECT * FROM infrastructure_providers WHERE id=?", (provider_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="infrastructure provider not found")
    return row


def _get_artifact_mirror_item(conn, artifact_id: str):
    row = conn.execute("SELECT * FROM artifact_mirror_items WHERE id=?", (artifact_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="artifact mirror item not found")
    return row


def _infrastructure_provider_snapshot(conn, provider_id: str) -> dict[str, Any]:
    provider = _infrastructure_provider_dict(_get_infrastructure_provider(conn, provider_id))
    snapshot = {
        "id": provider["id"],
        "name": provider["name"],
        "kind": provider["kind"],
        "endpoint": provider["endpoint"],
        "credential_ref": provider["credential_ref"],
        "credential_snapshot": _credential_snapshot(conn, provider["credential_ref"]),
        "api_version": provider["api_version"],
        "implementation_version": provider["implementation_version"],
        "site": provider["site"],
        "zone": provider["zone"],
        "capabilities": provider["capabilities"],
        "labels": provider["labels"],
        "health_status": provider["health_status"],
        "status": provider["status"],
    }
    snapshot["snapshot_hash"] = sha256_hex(snapshot)
    return snapshot


def _artifact_mirror_snapshot(conn, artifact_id: str) -> dict[str, Any]:
    artifact = _artifact_mirror_item_dict(_get_artifact_mirror_item(conn, artifact_id))
    snapshot = {
        "id": artifact["id"],
        "name": artifact["name"],
        "kind": artifact["kind"],
        "source": artifact["source"],
        "destination": artifact["destination"],
        "version": artifact["version"],
        "digest": artifact["digest"],
        "labels": artifact["labels"],
        "status": artifact["status"],
    }
    snapshot["snapshot_hash"] = sha256_hex(snapshot)
    return snapshot


def _get_blueprint(conn, blueprint_id: str):
    row = conn.execute("SELECT * FROM cluster_blueprints WHERE id=?", (blueprint_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="cluster blueprint not found")
    return row


def _get_profile(conn, profile_id: str):
    row = conn.execute("SELECT * FROM cluster_profiles WHERE id=?", (profile_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="cluster profile not found")
    return row


def _get_cluster(conn, cluster_id: str):
    row = conn.execute("SELECT * FROM clusters WHERE id=?", (cluster_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="cluster not found")
    return row


def _cluster_snapshot(conn, cluster_id: str) -> dict[str, Any]:
    cluster = _cluster_dict(_get_cluster(conn, cluster_id))
    profile = _profile_dict(_get_profile(conn, cluster["profile_id"]))
    blueprint = _blueprint_dict(_get_blueprint(conn, profile["blueprint_id"]))
    roles = [_node_role_dict(row) for row in conn.execute("SELECT * FROM node_roles WHERE profile_id=? AND status='configured' ORDER BY id", (profile["id"],)).fetchall()]
    servers = [_server_snapshot(conn, server_id) for server_id in sorted(profile["server_ids"])]
    snapshot = {
        "entity_type": "cluster",
        "kind": "kubernetes-cluster",
        "id": cluster["id"],
        "name": cluster["name"],
        "environment_id": cluster["environment_id"],
        "profile_id": cluster["profile_id"],
        "provider": cluster["provider"],
        "kubernetes_version": cluster["kubernetes_version"],
        "network_plugin": cluster["network_plugin"],
        "state": cluster["state"],
        "status": cluster["status"],
        "blueprint": {"id": blueprint["id"], "provider": blueprint["provider"], "provider_version": blueprint["provider_version"], "kubernetes_version": blueprint["kubernetes_version"], "network_plugin": blueprint["network_plugin"], "hubble_enabled": blueprint["hubble_enabled"], "radar_enabled": blueprint["radar_enabled"], "addon_versions": blueprint["addon_versions"]},
        "node_roles": [{"id": role["id"], "role": role["role"], "server_ids": role["server_ids"]} for role in roles],
        "server_snapshots": servers,
    }
    if blueprint.get("artifact_dependencies"):
        artifact_manifest = _blueprint_artifact_manifest(conn, blueprint["id"])
        snapshot["blueprint_artifact_manifest_hash"] = artifact_manifest.get("manifest_hash")
        snapshot["blueprint_artifact_manifest_state"] = artifact_manifest.get("state")
        if artifact_manifest.get("state") == "READY" and not artifact_manifest.get("issues"):
            try:
                snapshot["artifact_supply"] = cluster_factory.offline_artifact_supply(artifact_manifest)
            except ValueError:
                snapshot["artifact_supply"] = None
    snapshot["snapshot_hash"] = sha256_hex(snapshot)
    return snapshot


def _application_dict(row: Any) -> dict[str, Any]:
    return _row_json(
        row,
        {
            "values_files_json": "values_files",
            "verification_checks_json": "verification_checks",
            "rollback_strategy_json": "rollback_strategy",
            "labels_json": "labels",
        },
    )

def _agent_task_dict(row: Any) -> dict[str, Any]:
    item = dict(row)
    item["envelope"] = json.loads(item.pop("envelope_json") or "{}")
    item["result"] = json.loads(item.pop("result_json") or "null")
    item.pop("claim_nonce_hash", None)
    return item


def _credential_snapshot(conn, credential_ref: str | None) -> dict[str, Any] | None:
    if not credential_ref:
        return None
    row = _get_credential_ref(conn, credential_ref)
    return {
        "id": row["id"],
        "kind": row["kind"],
        "provider": row["provider"],
        "status": row["status"],
        "metadata": json.loads(row["metadata_json"] or "{}"),
        "updated_at": row["updated_at"],
    }


_SECRET_METADATA_KEYS = {
    "secret", "password", "passphrase", "token", "access_token", "refresh_token",
    "private_key", "privatekey", "kubeconfig", "credential", "credentials", "raw", "content", "value",
    "api_key", "secret_key", "client_secret", "user_data", "cloud_init", "authorization", "bearer",
}


def _validate_credential_metadata(metadata: dict[str, Any]) -> None:
    def walk(value: Any, path: str = "metadata") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = str(key).strip().lower().replace("-", "_")
                if normalized in _SECRET_METADATA_KEYS or normalized.endswith("_secret") or normalized.endswith("_password") or normalized.endswith("_token") or normalized.endswith("_private_key"):
                    raise HTTPException(status_code=422, detail=f"raw secret material is forbidden in credential reference {path}.{key}")
                walk(child, f"{path}.{key}")
        elif isinstance(value, list):
            for idx, child in enumerate(value):
                walk(child, f"{path}[{idx}]")
    walk(metadata)


def _reject_embedded_url_credentials(value: str, field: str) -> None:
    parsed = urlparse(value)
    if parsed.username is not None or parsed.password is not None:
        raise HTTPException(status_code=422, detail=f"raw credentials are forbidden in {field}; use a Credential Service reference")


def _target_snapshot(conn, target_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
    if not row:
        if target_id.startswith("srv_"):
            return _server_snapshot(conn, target_id)
        if target_id.startswith("clu_"):
            return _cluster_snapshot(conn, target_id)
        if target_id.startswith("ipr_"):
            return _infrastructure_provider_snapshot(conn, target_id)
        if target_id.startswith("art_"):
            return _artifact_mirror_snapshot(conn, target_id)
        if target_id.startswith("flt_"):
            fleet = conn.execute("SELECT * FROM fleet_target_snapshots WHERE id=?", (target_id,)).fetchone()
            if not fleet:
                raise HTTPException(status_code=404, detail="fleet target snapshot not found")
            return {
                "id": fleet["id"],
                "kind": "fleet-target-snapshot",
                "selector": json.loads(fleet["selector_json"] or "{}"),
                "targets": json.loads(fleet["targets_json"] or "[]"),
                "snapshot_hash": fleet["snapshot_hash"],
                "status": fleet["status"],
            }
        raise HTTPException(status_code=404, detail="target not found")
    target = _target_dict(row)
    snapshot = {
        "id": target["id"],
        "name": target["name"],
        "kind": target["kind"],
        "environment_id": target["environment_id"],
        "integration_id": target["integration_id"],
        "credential_ref": target["credential_ref"],
        "connection_mode": target["connection_mode"],
        "address": target["address"],
        "scope": target["scope"],
        "status": target["status"],
        "credential_snapshot": _credential_snapshot(conn, target["credential_ref"]),
    }
    snapshot["snapshot_hash"] = sha256_hex(snapshot)
    return snapshot


def _provider_job_dict(row: Any) -> dict[str, Any]:
    item = dict(row)
    item["request"] = json.loads(item.pop("request_json") or "{}")
    item["result"] = json.loads(item.pop("result_json") or "null")
    return item


def _provider_job_authorization(conn, job: Any) -> Any:
    changeset = _changeset(conn, job["changeset_id"])
    _require_current_policy_generation(conn, changeset)
    required_state = "APPROVED" if changeset["approval_required"] else "PREVIEWED"
    if changeset["state"] != required_state:
        raise HTTPException(status_code=409, detail=f"provider job requires ChangeSet state {required_state}")
    if changeset["plan_hash"] != job["plan_hash"]:
        raise HTTPException(status_code=409, detail="provider job plan hash no longer matches ChangeSet")
    request = json.loads(job["request_json"] or "{}")
    artifact_manifest_hash = str(request.get("artifact_manifest_hash") or "")
    if artifact_manifest_hash:
        cluster_id = str(request.get("cluster_id") or "")
        cluster = _cluster_dict(_get_cluster(conn, cluster_id))
        profile = _profile_dict(_get_profile(conn, cluster["profile_id"]))
        blueprint = _blueprint_dict(_get_blueprint(conn, profile["blueprint_id"]))
        current_manifest = _blueprint_artifact_manifest(conn, blueprint["id"])
        if current_manifest.get("state") != "READY" or current_manifest.get("manifest_hash") != artifact_manifest_hash:
            raise HTTPException(status_code=409, detail="cluster blueprint artifact manifest drifted after provisioning plan approval")
    return changeset


def _issue_provider_job_ticket(conn, job: Any, changeset: Any) -> tuple[dict[str, Any], str, list[str]]:
    now = int(time.time())
    changeset_plan = json.loads(changeset["plan_json"] or "{}")
    typed_plan = ((changeset_plan.get("parameters") or {}).get("typed_plan") or {})
    if not isinstance(typed_plan, dict) or not typed_plan.get("plan_hash"):
        raise HTTPException(status_code=409, detail="provider job ChangeSet has no exact typed plan")
    approval_ids = _valid_operation_approval_ids(conn, changeset, now=now)
    expiry_candidates = [int(changeset["expires_at"] or now + 120)]
    if approval_ids:
        placeholders = ",".join("?" for _ in approval_ids)
        rows = conn.execute(f"SELECT expires_at FROM approvals WHERE id IN ({placeholders})", approval_ids).fetchall()
        expiry_candidates.extend(int(row["expires_at"]) for row in rows)
    ttl_seconds = max(1, min(120, min(expiry_candidates) - now))
    request = json.loads(job["request_json"] or "{}")
    preconditions = {
        "provider_job_id": job["id"],
        "executor": "cluster-provider-worker",
        "typed_plan_hash": typed_plan["plan_hash"],
        "policy_generation": int(changeset["policy_generation"]),
        "artifact_manifest_hash": str(request.get("artifact_manifest_hash") or (typed_plan.get("artifact_supply") or {}).get("manifest_hash") or ""),
    }
    try:
        ticket, signature = issue_ticket(changeset["id"], changeset["plan_hash"], changeset_plan, ttl_seconds=ttl_seconds, preconditions=preconditions)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    request["authorization"] = {
        "ticket_hash": sha256_hex(ticket),
        "issued_at": ticket["issued_at"],
        "expires_at": ticket["expires_at"],
        "approval_ids": approval_ids,
        "policy_generation": int(changeset["policy_generation"]),
        "plan_hash": changeset["plan_hash"],
    }
    conn.execute("UPDATE provider_jobs SET request_json=?,updated_at=? WHERE id=?", (json.dumps(request, sort_keys=True), now, job["id"]))
    return ticket, signature, approval_ids


def _verify_provider_job_ticket(conn, job: Any, ticket: dict[str, Any], signature: str) -> tuple[Any, dict[str, Any], dict[str, Any], list[str]]:
    changeset = _provider_job_authorization(conn, job)
    changeset_plan = json.loads(changeset["plan_json"] or "{}")
    typed_plan = ((changeset_plan.get("parameters") or {}).get("typed_plan") or {})
    request = json.loads(job["request_json"] or "{}")
    authorization = request.get("authorization") or {}
    if not authorization.get("ticket_hash"):
        raise HTTPException(status_code=409, detail="provider job has no issued execution ticket")
    try:
        verify_ticket(ticket, signature, require_fresh=True)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if sha256_hex(ticket) != authorization.get("ticket_hash"):
        raise HTTPException(status_code=409, detail="execution ticket does not match the authorized provider job")
    if ticket.get("changeset_id") != changeset["id"] or ticket.get("plan_hash") != changeset["plan_hash"] or ticket.get("plan") != changeset_plan:
        raise HTTPException(status_code=409, detail="provider execution ticket ChangeSet binding mismatch")
    expected = {
        "provider_job_id": job["id"],
        "executor": "cluster-provider-worker",
        "typed_plan_hash": typed_plan.get("plan_hash"),
        "policy_generation": int(changeset["policy_generation"]),
        "artifact_manifest_hash": str(request.get("artifact_manifest_hash") or (typed_plan.get("artifact_supply") or {}).get("manifest_hash") or ""),
    }
    if (ticket.get("preconditions") or {}) != expected:
        raise HTTPException(status_code=409, detail="provider execution ticket preconditions mismatch")
    current_ids = _valid_operation_approval_ids(conn, changeset, now=int(time.time()))
    if set(current_ids) != set(authorization.get("approval_ids") or []):
        raise HTTPException(status_code=409, detail="provider execution ticket approvals no longer match exact-plan authorization")
    return changeset, changeset_plan, typed_plan, current_ids


def _persist_provider_job_verification(conn, *, job: Any, changeset: Any, runtime_result: dict[str, Any], actor: str) -> dict[str, Any]:
    verification = runtime_result.get("verification") or {}
    checks = verification.get("checks") or []
    if not isinstance(checks, list) or not checks:
        raise HTTPException(status_code=502, detail="provider worker returned no typed active verification")
    normalized = []
    for check in checks:
        if not isinstance(check, dict):
            raise HTTPException(status_code=502, detail="provider worker returned malformed verification")
        item = {
            "id": str(check.get("id") or "")[:160],
            "status": str(check.get("status") or ""),
            "summary": str(check.get("summary") or "")[:1000],
            "evidence": check.get("evidence") if isinstance(check.get("evidence"), dict) else {},
        }
        if not item["id"] or item["status"] not in {"PASS", "FAIL", "WARN", "SKIP"} or not item["summary"]:
            raise HTTPException(status_code=502, detail="provider worker returned invalid verification fields")
        _validate_credential_metadata(item["evidence"])
        normalized.append(item)
    evidence = verification.get("evidence") if isinstance(verification.get("evidence"), dict) else {}
    _validate_credential_metadata(evidence)
    statuses = {item["status"] for item in normalized}
    overall = "FAIL" if "FAIL" in statuses else "WARN" if "WARN" in statuses else "SKIP" if statuses == {"SKIP"} else "PASS"
    result_id = f"ver_{uuid.uuid4().hex[:16]}"
    observed_at = int(verification.get("observed_at") or time.time())
    now = int(time.time())
    request = json.loads(job["request_json"] or "{}")
    cluster_id = str(request.get("cluster_id") or changeset["target_id"])
    conn.execute(
        "INSERT INTO verification_results (id,operation_plan_id,changeset_id,subject_type,subject_id,status,checks_json,evidence_json,observed_at,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (result_id, None, changeset["id"], "cluster", cluster_id, overall, json.dumps(normalized, sort_keys=True), json.dumps(evidence, sort_keys=True), observed_at, now),
    )
    db.audit(conn, "verification.provider_runtime_recorded", actor, "verification", result_id, {"provider_job_id": job["id"], "changeset_id": changeset["id"], "status": overall})
    return {"id": result_id, "status": overall, "checks": normalized, "evidence": evidence, "observed_at": observed_at}


def _provider_job_event(conn, job_id: str, stage: str, status: str, message: str, evidence: dict[str, Any] | None = None) -> None:
    _validate_credential_metadata(evidence or {})
    conn.execute(
        "INSERT INTO provider_job_events (job_id,stage,status,message,evidence_json,created_at) VALUES (?,?,?,?,?,?)",
        (job_id, stage, status, message, json.dumps(evidence or {}, sort_keys=True), int(time.time())),
    )


def _changeset_dict(row: Any) -> dict[str, Any]:
    item = dict(row)
    item["parameters"] = json.loads(item.pop("parameters_json") or "{}")
    item["plan"] = json.loads(item.pop("plan_json") or "{}")
    item["preview"] = json.loads(item.pop("preview_json") or "null")
    item["execution"] = json.loads(item.pop("execution_json", None) or "null")
    item["approval_required"] = bool(item["approval_required"])
    enabled = os.getenv("HERMES_EXECUTION_ENABLED", "false").lower() == "true"
    execution_state_ready = (
        item["state"] == "APPROVED"
        or (
            item["state"] == "PREVIEWED"
            and not item["approval_required"]
        )
    )
    item["executable"] = (
        enabled
        and item["adapter"] in {"kubernetes", "helm"}
        and execution_state_ready
    )
    item["execution_note"] = "execution requires a live broker preview, current policy generation, integrity-bound approval when required, target snapshot match, and a signed one-time broker ticket"
    return item


def _changeset(conn, changeset_id: str):
    row = conn.execute("SELECT * FROM changesets WHERE id=?", (changeset_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="changeset not found")
    if row["expires_at"] and int(row["expires_at"]) < int(time.time()) and row["state"] not in TERMINAL_CHANGESET_STATES:
        conn.execute("UPDATE changesets SET state='EXPIRED', updated_at=? WHERE id=?", (int(time.time()), changeset_id))
        db.audit(conn, "changeset.expired", "system", "changeset", changeset_id, {"plan_hash": row["plan_hash"]})
        conn.commit()
        row = conn.execute("SELECT * FROM changesets WHERE id=?", (changeset_id,)).fetchone()
    return row


@app.get("/")
def root() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/ui")
def ui() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True, "service": "hermes-control-plane", "version": VERSION}


@app.get("/v1/system")
def system() -> dict[str, Any]:
    with closing(db.connect()) as conn:
        counts = {
            "environments": conn.execute("SELECT COUNT(*) FROM environments").fetchone()[0],
            "integrations": conn.execute("SELECT COUNT(*) FROM integrations").fetchone()[0],
            "targets": conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0],
            "credential_refs": conn.execute("SELECT COUNT(*) FROM credential_refs").fetchone()[0],
            "servers": conn.execute("SELECT COUNT(*) FROM servers").fetchone()[0],
            "provider_jobs": conn.execute("SELECT COUNT(*) FROM provider_jobs").fetchone()[0],
            "cluster_blueprints": conn.execute("SELECT COUNT(*) FROM cluster_blueprints").fetchone()[0],
            "cluster_profiles": conn.execute("SELECT COUNT(*) FROM cluster_profiles").fetchone()[0],
            "clusters": conn.execute("SELECT COUNT(*) FROM clusters").fetchone()[0],
            "provisioning_runs": conn.execute("SELECT COUNT(*) FROM provisioning_runs").fetchone()[0],
            "changesets": conn.execute("SELECT COUNT(*) FROM changesets").fetchone()[0],
            "applications": conn.execute("SELECT COUNT(*) FROM applications").fetchone()[0],
            "agents": conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0],
            "agent_tasks": conn.execute("SELECT COUNT(*) FROM agent_tasks").fetchone()[0],
            "infrastructure_providers": conn.execute("SELECT COUNT(*) FROM infrastructure_providers").fetchone()[0],
            "operation_plans": conn.execute("SELECT COUNT(*) FROM operation_plans").fetchone()[0],
            "operation_jobs": conn.execute("SELECT COUNT(*) FROM operation_jobs").fetchone()[0],
            "artifact_mirror_items": conn.execute("SELECT COUNT(*) FROM artifact_mirror_items").fetchone()[0],
            "verification_results": conn.execute("SELECT COUNT(*) FROM verification_results").fetchone()[0],
        }
        policy_generation = db.get_policy_generation(conn)
    return {
        "name": "Hermes Control Plane",
        "version": VERSION,
        "stage": "development",
        "runtime": os.getenv("HERMES_RUNTIME", "docker"),
        "capabilities": ["integration-registry", "target-registry", "application-registry", "adapter-capability-contract", "credential-references", "server-registry", "ssh-preflight", "provider-lifecycle-contract", "bootstrap-jobs", "cluster-factory", "cluster-blueprints", "cluster-profiles", "node-roles", "provisioning-runs", "addon-plans", "upgrade-plans", "backup-plans", "kubespray-production-path", "k3s-edge-path", "rke2-hardened-path", "cilium-hubble", "radar-kubernetes-intelligence", "native-diagnostics", "operator-center-ui", "operations-center", "shared-intent-backend", "fleet-registry", "fleet-exact-target-snapshots", "advanced-day2-plans", "bare-metal-provider-contracts", "switch-network-provider-contracts", "vmware-provider-foundation", "openstack-provider-foundation", "aws-provider-foundation", "azure-provider-foundation", "gcp-provider-foundation", "airgap-artifact-mirror", "unified-verification", "generic-operation-jobs", "target-drift-rejection", "changeset-planning", "risk-engine", "approval-binding", "audit", "agent-enrollment", "agent-signed-task-envelope", "kubernetes-discovery", "kubernetes-server-dry-run", "kubernetes-guarded-delete", "kubernetes-rollback", "kubernetes-rollout-verification", "helm-server-dry-run", "helm-rollback", "signed-execution-tickets"],
        "execution_enabled": os.getenv("HERMES_EXECUTION_ENABLED", "false").lower() == "true",
        "policy_generation": policy_generation,
        "mutation_control": {
            "infrastructure_mutations": "bot-only-changeset",
            "radar_hubble_mutations": "changeset-policy-approval-only",
            "kubernetes_helm": "bot-only",
            "approval": "approval-bot-only",
            "ui": "configuration-and-observability; mutations enter the same bot-authenticated intent backend",
            "fleet_cloud_baremetal_network_artifact": "typed-plan-changeset-exact-hash-operation-job-verification",
        },
        "counts": counts,
    }


@app.post("/v1/policy-generation/bump")
def bump_policy_generation(payload: PolicyGenerationBump, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        old, new = db.bump_policy_generation(conn, payload.actor, payload.reason)
        conn.commit()
    return {"old_generation": old, "policy_generation": new, "actor": payload.actor, "reason": payload.reason}


@app.get("/v1/capabilities")
def list_capabilities() -> list[dict[str, Any]]:
    return [{"id": capability_id, **spec} for capability_id, spec in sorted(ADAPTER_CAPABILITIES.items())]


@app.get("/v1/environments")
def list_environments() -> list[dict[str, Any]]:
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM environments ORDER BY name").fetchall()
    return [_row_json(row, {"labels_json": "labels"}) for row in rows]


@app.post("/v1/environments", status_code=201)
def create_environment(payload: EnvironmentCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    slug = db.slugify(payload.slug or payload.name)
    env_id = f"env_{uuid.uuid4().hex[:16]}"
    now = int(time.time())
    with closing(db.connect()) as conn:
        try:
            conn.execute(
                "INSERT INTO environments (id,name,slug,risk_level,labels_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
                (env_id, payload.name, slug, payload.risk_level, json.dumps(payload.labels, sort_keys=True), now, now),
            )
            db.audit(conn, "environment.created", "admin", "environment", env_id, {"name": payload.name, "risk_level": payload.risk_level})
            conn.commit()
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise HTTPException(status_code=409, detail="environment name or slug already exists") from exc
            raise
    return {"id": env_id, "name": payload.name, "slug": slug, "risk_level": payload.risk_level, "labels": payload.labels, "created_at": now, "updated_at": now}


@app.patch("/v1/environments/{environment_id}")
def update_environment(environment_id: str, payload: EnvironmentUpdate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="no fields supplied")
    if "metadata" in updates:
        _validate_credential_metadata(updates["metadata"])
    with closing(db.connect()) as conn:
        _get_environment(conn, environment_id)
        if "labels" in updates:
            updates["labels_json"] = json.dumps(updates.pop("labels"), sort_keys=True)
        updates["updated_at"] = int(time.time())
        fields = list(updates)
        conn.execute(f"UPDATE environments SET {', '.join(f'{f}=?' for f in fields)} WHERE id=?", (*[updates[f] for f in fields], environment_id))
        db.audit(conn, "environment.updated", "admin", "environment", environment_id, {"fields": fields})
        conn.commit()
        row = conn.execute("SELECT * FROM environments WHERE id=?", (environment_id,)).fetchone()
    return _row_json(row, {"labels_json": "labels"})


@app.delete("/v1/environments/{environment_id}", status_code=204)
def delete_environment(environment_id: str, authorization: str | None = Header(default=None)) -> None:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        if conn.execute("SELECT 1 FROM integrations WHERE environment_id=? LIMIT 1", (environment_id,)).fetchone() or conn.execute("SELECT 1 FROM targets WHERE environment_id=? LIMIT 1", (environment_id,)).fetchone():
            raise HTTPException(status_code=409, detail="environment is in use")
        cur = conn.execute("DELETE FROM environments WHERE id=?", (environment_id,))
        if not cur.rowcount:
            raise HTTPException(status_code=404, detail="environment not found")
        db.audit(conn, "environment.deleted", "admin", "environment", environment_id)
        conn.commit()


@app.post("/v1/internal/credential-refs/sync")
def sync_credential_ref(payload: CredentialRefSync, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_credential_service(authorization)
    _validate_credential_metadata(payload.metadata)
    now = int(time.time())
    with closing(db.connect()) as conn:
        existing = conn.execute("SELECT * FROM credential_refs WHERE id=?", (payload.id,)).fetchone()
        name_owner = conn.execute("SELECT id FROM credential_refs WHERE name=?", (payload.name,)).fetchone()
        if name_owner and name_owner["id"] != payload.id:
            raise HTTPException(status_code=409, detail="credential reference name already exists")
        if existing:
            conn.execute(
                "UPDATE credential_refs SET name=?,kind=?,provider=?,status=?,metadata_json=?,updated_at=? WHERE id=?",
                (payload.name, payload.kind, payload.provider, payload.status, json.dumps(payload.metadata, sort_keys=True), now, payload.id),
            )
            event = "credential_ref.synced"
        else:
            conn.execute(
                "INSERT INTO credential_refs (id,name,kind,provider,status,metadata_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (payload.id, payload.name, payload.kind, payload.provider, payload.status, json.dumps(payload.metadata, sort_keys=True), now, now),
            )
            event = "credential_ref.synced_created"
        db.audit(conn, event, "credential-service", "credential_ref", payload.id, {"kind": payload.kind, "provider": payload.provider, "metadata_only": True})
        conn.commit()
        row = conn.execute("SELECT * FROM credential_refs WHERE id=?", (payload.id,)).fetchone()
    return _row_json(row, {"metadata_json": "metadata"})


@app.delete("/v1/internal/credential-refs/{credential_id}", status_code=204)
def delete_synced_credential_ref(credential_id: str, authorization: str | None = Header(default=None)) -> None:
    _require_credential_service(authorization)
    with closing(db.connect()) as conn:
        if (conn.execute("SELECT 1 FROM integrations WHERE credential_ref=? LIMIT 1", (credential_id,)).fetchone()
                or conn.execute("SELECT 1 FROM targets WHERE credential_ref=? LIMIT 1", (credential_id,)).fetchone()
                or conn.execute("SELECT 1 FROM servers WHERE credential_ref=? OR bmc_credential_ref=? LIMIT 1", (credential_id, credential_id)).fetchone()):
            raise HTTPException(status_code=409, detail="credential reference is in use")
        cur = conn.execute("DELETE FROM credential_refs WHERE id=?", (credential_id,))
        if not cur.rowcount:
            raise HTTPException(status_code=404, detail="credential reference not found")
        db.audit(conn, "credential_ref.synced_deleted", "credential-service", "credential_ref", credential_id, {"metadata_only": True})
        conn.commit()


@app.get("/v1/credential-refs")
def list_credential_refs() -> list[dict[str, Any]]:
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM credential_refs ORDER BY name").fetchall()
    return [_row_json(row, {"metadata_json": "metadata"}) for row in rows]


@app.post("/v1/credential-refs", status_code=201)
def create_credential_ref(payload: CredentialRefCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    _validate_credential_metadata(payload.metadata)
    cred_id = f"cred_{uuid.uuid4().hex[:16]}"
    now = int(time.time())
    with closing(db.connect()) as conn:
        try:
            conn.execute(
                "INSERT INTO credential_refs (id,name,kind,provider,status,metadata_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (cred_id, payload.name, payload.kind, payload.provider, "configured", json.dumps(payload.metadata, sort_keys=True), now, now),
            )
            db.audit(conn, "credential_ref.created", "admin", "credential_ref", cred_id, {"kind": payload.kind, "provider": payload.provider})
            conn.commit()
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise HTTPException(status_code=409, detail="credential reference name already exists") from exc
            raise
    return {"id": cred_id, **payload.model_dump(), "status": "configured", "created_at": now, "updated_at": now, "secret_material_stored": False}


@app.patch("/v1/credential-refs/{credential_id}")
def update_credential_ref(credential_id: str, payload: CredentialRefUpdate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="no fields supplied")
    with closing(db.connect()) as conn:
        if not conn.execute("SELECT 1 FROM credential_refs WHERE id=?", (credential_id,)).fetchone():
            raise HTTPException(status_code=404, detail="credential reference not found")
        if "metadata" in updates:
            _validate_credential_metadata(updates["metadata"])
            updates["metadata_json"] = json.dumps(updates.pop("metadata"), sort_keys=True)
        updates["updated_at"] = int(time.time())
        fields = list(updates)
        conn.execute(f"UPDATE credential_refs SET {', '.join(f'{f}=?' for f in fields)} WHERE id=?", (*[updates[f] for f in fields], credential_id))
        db.audit(conn, "credential_ref.updated", "admin", "credential_ref", credential_id, {"fields": fields})
        conn.commit()
        row = conn.execute("SELECT * FROM credential_refs WHERE id=?", (credential_id,)).fetchone()
    return _row_json(row, {"metadata_json": "metadata"})


@app.post("/v1/credential-refs/{credential_id}/rotate")
def rotate_credential_ref(credential_id: str, payload: CredentialRefUpdate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    updates = payload.model_dump(exclude_unset=True)
    metadata = updates.get("metadata")
    if metadata is None:
        raise HTTPException(status_code=422, detail="rotation requires replacement reference metadata/fingerprint")
    _validate_credential_metadata(metadata)
    now = int(time.time())
    with closing(db.connect()) as conn:
        row = conn.execute("SELECT * FROM credential_refs WHERE id=?", (credential_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="credential reference not found")
        old_meta = json.loads(row["metadata_json"] or "{}")
        conn.execute("UPDATE credential_refs SET status='configured',metadata_json=?,updated_at=? WHERE id=?", (json.dumps(metadata, sort_keys=True), now, credential_id))
        db.audit(conn, "credential_ref.rotated", "admin", "credential_ref", credential_id, {
            "old_fingerprint": old_meta.get("sha256") or old_meta.get("fingerprint"),
            "new_fingerprint": metadata.get("sha256") or metadata.get("fingerprint"),
        })
        conn.commit()
        updated = conn.execute("SELECT * FROM credential_refs WHERE id=?", (credential_id,)).fetchone()
    return _row_json(updated, {"metadata_json": "metadata"})


@app.delete("/v1/credential-refs/{credential_id}", status_code=204)
def delete_credential_ref(credential_id: str, authorization: str | None = Header(default=None)) -> None:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        if (conn.execute("SELECT 1 FROM integrations WHERE credential_ref=? LIMIT 1", (credential_id,)).fetchone()
                or conn.execute("SELECT 1 FROM targets WHERE credential_ref=? LIMIT 1", (credential_id,)).fetchone()
                or conn.execute("SELECT 1 FROM servers WHERE credential_ref=? OR bmc_credential_ref=? LIMIT 1", (credential_id, credential_id)).fetchone()):
            raise HTTPException(status_code=409, detail="credential reference is in use")
        cur = conn.execute("DELETE FROM credential_refs WHERE id=?", (credential_id,))
        if not cur.rowcount:
            raise HTTPException(status_code=404, detail="credential reference not found")
        db.audit(conn, "credential_ref.deleted", "admin", "credential_ref", credential_id)
        conn.commit()


@app.get("/v1/agents")
def list_agents(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT id,name,status,capabilities_json,enrolled_at,last_seen_at,revoked_at FROM agents ORDER BY name").fetchall()
    return [{**dict(row), "capabilities": json.loads(row["capabilities_json"] or "[]")} | {"capabilities_json": None} for row in rows]


@app.post("/v1/agents/enrollment-tokens", status_code=201)
def create_agent_enrollment_token(payload: AgentEnrollmentTokenCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    now = int(time.time())
    token_id = f"aen_{uuid.uuid4().hex[:16]}"
    token = secrets.token_urlsafe(32)
    expires_at = now + payload.ttl_seconds
    with closing(db.connect()) as conn:
        if conn.execute("SELECT 1 FROM agents WHERE name=?", (payload.name,)).fetchone():
            raise HTTPException(status_code=409, detail="agent name is already enrolled")
        conn.execute(
            "INSERT INTO agent_enrollment_tokens (id,name,token_hash,status,expires_at,created_at) VALUES (?,?,?,?,?,?)",
            (token_id, payload.name, _hash_token(token), "ISSUED", expires_at, now),
        )
        db.audit(conn, "agent.enrollment_token_issued", "admin", "agent_enrollment", token_id, {"name": payload.name, "expires_at": expires_at})
        conn.commit()
    return {"id": token_id, "name": payload.name, "enrollment_token": token, "expires_at": expires_at}


@app.post("/v1/agents/enroll", status_code=201)
def enroll_agent(payload: AgentEnroll) -> dict[str, Any]:
    now = int(time.time())
    token_hash = _hash_token(payload.enrollment_token)
    with closing(db.connect()) as conn:
        row = conn.execute("SELECT * FROM agent_enrollment_tokens WHERE token_hash=?", (token_hash,)).fetchone()
        if not row or row["status"] != "ISSUED" or int(row["expires_at"]) < now:
            raise HTTPException(status_code=401, detail="invalid, expired, or already-used enrollment token")
        if conn.execute("SELECT 1 FROM agents WHERE name=?", (row["name"],)).fetchone():
            raise HTTPException(status_code=409, detail="agent name is already enrolled")
        agent_id = f"agt_{uuid.uuid4().hex[:16]}"
        bearer = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO agents (id,name,token_hash,status,capabilities_json,enrolled_at) VALUES (?,?,?,?,?,?)",
            (agent_id, row["name"], _hash_token(bearer), "ACTIVE", json.dumps(payload.capabilities, sort_keys=True), now),
        )
        conn.execute("UPDATE agent_enrollment_tokens SET status='USED',used_at=? WHERE id=? AND status='ISSUED'", (now, row["id"]))
        db.audit(conn, "agent.enrolled", row["name"], "agent", agent_id, {"capabilities": payload.capabilities})
        conn.commit()
    return {"id": agent_id, "name": row["name"], "agent_token": bearer, "status": "ACTIVE", "capabilities": payload.capabilities, "enrolled_at": now}


def _authorized_agent(conn, authorization: str | None) -> Any:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing agent bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    row = conn.execute("SELECT * FROM agents WHERE token_hash=?", (_hash_token(token),)).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="invalid agent bearer token")
    if row["status"] != "ACTIVE":
        raise HTTPException(status_code=403, detail="agent identity is revoked")
    return row


@app.post("/v1/agents/heartbeat")
def agent_heartbeat(payload: AgentHeartbeat, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    now = int(time.time())
    with closing(db.connect()) as conn:
        agent = _authorized_agent(conn, authorization)
        try:
            conn.execute("INSERT INTO agent_nonces (agent_id,nonce,seen_at) VALUES (?,?,?)", (agent["id"], payload.nonce, now))
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise HTTPException(status_code=409, detail="agent nonce replay rejected") from exc
            raise
        capabilities = payload.capabilities if payload.capabilities is not None else json.loads(agent["capabilities_json"] or "[]")
        conn.execute("UPDATE agents SET capabilities_json=?,last_seen_at=? WHERE id=?", (json.dumps(capabilities, sort_keys=True), now, agent["id"]))
        db.audit(conn, "agent.heartbeat", agent["name"], "agent", agent["id"], {"nonce_sha256": _hash_token(payload.nonce), "capabilities": capabilities})
        conn.commit()
    return {"id": agent["id"], "status": "ACTIVE", "last_seen_at": now, "capabilities": capabilities}


@app.post("/v1/agents/{agent_id}/revoke")
def revoke_agent(agent_id: str, payload: AgentRevoke, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    now = int(time.time())
    with closing(db.connect()) as conn:
        row = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="agent not found")
        conn.execute("UPDATE agents SET status='REVOKED',revoked_at=? WHERE id=?", (now, agent_id))
        db.audit(conn, "agent.revoked", payload.actor, "agent", agent_id, {"reason": payload.reason})
        conn.commit()
    return {"id": agent_id, "status": "REVOKED", "revoked_at": now}


@app.get("/v1/agent-tasks")
def list_agent_tasks(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM agent_tasks ORDER BY issued_at DESC, id DESC").fetchall()
    return [_agent_task_dict(row) for row in rows]


@app.post("/v1/agents/{agent_id}/tasks", status_code=201)
def issue_agent_task(agent_id: str, payload: AgentTaskCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    now = int(time.time())
    with closing(db.connect()) as conn:
        agent = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="agent not found")
        if agent["status"] != "ACTIVE":
            raise HTTPException(status_code=409, detail="agent is not active")
        capabilities = set(json.loads(agent["capabilities_json"] or "[]"))
        if payload.capability not in capabilities:
            raise HTTPException(status_code=403, detail="agent did not advertise the requested capability")
        capability = ADAPTER_CAPABILITIES.get(payload.capability)
        if not capability:
            raise HTTPException(status_code=422, detail="unknown adapter capability")

        changeset = _changeset(conn, payload.changeset_id)
        _require_current_policy_generation(conn, changeset)
        target_snapshot = _target_snapshot(conn, changeset["target_id"])
        if target_snapshot.get("connection_mode") != "agent":
            raise HTTPException(status_code=409, detail="ChangeSet target is not configured for agent execution")
        if capability["adapter"] != changeset["adapter"]:
            raise HTTPException(status_code=409, detail="capability adapter does not match ChangeSet adapter")
        if changeset["approval_required"]:
            if changeset["state"] != "APPROVED":
                raise HTTPException(status_code=409, detail="approved ChangeSet required before agent task issuance")
        elif changeset["state"] != "PREVIEWED":
            raise HTTPException(status_code=409, detail="previewed ChangeSet required before agent task issuance")

        task_id = f"tsk_{uuid.uuid4().hex[:16]}"
        expires_at = min(now + payload.ttl_seconds, int(changeset["expires_at"] or now + payload.ttl_seconds))
        envelope = {
            "schema_version": 1,
            "task_id": task_id,
            "agent_id": agent_id,
            "changeset_id": changeset["id"],
            "changeset_hash": changeset["plan_hash"],
            "capability": payload.capability,
            "target_id": changeset["target_id"],
            "policy_generation": int(changeset["policy_generation"]),
            "issued_at": now,
            "expires_at": expires_at,
            "nonce": secrets.token_urlsafe(24),
            "plan": json.loads(changeset["plan_json"] or "{}"),
        }
        signature = _agent_task_signature(envelope)
        conn.execute(
            "INSERT INTO agent_tasks (id,agent_id,changeset_id,capability,policy_generation,envelope_json,signature,state,issued_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (task_id, agent_id, changeset["id"], payload.capability, int(changeset["policy_generation"]), canonical_json(envelope), signature, "ISSUED", now, expires_at),
        )
        db.audit(conn, "agent.task_issued", "admin", "agent_task", task_id, {"agent_id": agent_id, "changeset_id": changeset["id"], "capability": payload.capability, "plan_hash": changeset["plan_hash"]})
        conn.commit()
        row = conn.execute("SELECT * FROM agent_tasks WHERE id=?", (task_id,)).fetchone()
    return _agent_task_dict(row)


@app.get("/v1/agents/tasks/next")
def next_agent_task(authorization: str | None = Header(default=None)) -> dict[str, Any] | None:
    now = int(time.time())
    with closing(db.connect()) as conn:
        agent = _authorized_agent(conn, authorization)
        conn.execute("UPDATE agent_tasks SET state='EXPIRED' WHERE agent_id=? AND state='ISSUED' AND expires_at<?", (agent["id"], now))
        row = conn.execute("SELECT * FROM agent_tasks WHERE agent_id=? AND state='ISSUED' ORDER BY issued_at,id LIMIT 1", (agent["id"],)).fetchone()
        conn.commit()
    return _agent_task_dict(row) if row else None


@app.post("/v1/agents/tasks/{task_id}/claim")
def claim_agent_task(task_id: str, payload: AgentTaskClaim, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    now = int(time.time())
    with closing(db.connect()) as conn:
        agent = _authorized_agent(conn, authorization)
        row = conn.execute("SELECT * FROM agent_tasks WHERE id=? AND agent_id=?", (task_id, agent["id"])).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="agent task not found")
        if row["state"] != "ISSUED":
            raise HTTPException(status_code=409, detail=f"agent task cannot be claimed from state {row['state']}")
        if int(row["expires_at"]) < now:
            conn.execute("UPDATE agent_tasks SET state='EXPIRED' WHERE id=?", (task_id,))
            conn.commit()
            raise HTTPException(status_code=409, detail="agent task expired")
        current_generation = db.get_policy_generation(conn)
        if int(row["policy_generation"]) != current_generation:
            conn.execute("UPDATE agent_tasks SET state='STALE_POLICY' WHERE id=?", (task_id,))
            db.audit(conn, "agent.task_stale_policy", agent["name"], "agent_task", task_id, {"task_generation": row["policy_generation"], "current_generation": current_generation})
            conn.commit()
            raise HTTPException(status_code=409, detail="agent task policy generation is stale")
        changeset = conn.execute("SELECT * FROM changesets WHERE id=?", (row["changeset_id"],)).fetchone()
        if not changeset:
            raise HTTPException(status_code=409, detail="agent task ChangeSet no longer exists")
        allowed_state = "APPROVED" if changeset["approval_required"] else "PREVIEWED"
        if changeset["state"] != allowed_state:
            conn.execute("UPDATE agent_tasks SET state='INVALIDATED' WHERE id=?", (task_id,))
            db.audit(conn, "agent.task_invalidated", agent["name"], "agent_task", task_id, {"changeset_state": changeset["state"], "required_state": allowed_state})
            conn.commit()
            raise HTTPException(status_code=409, detail="agent task ChangeSet is no longer authorized for execution")
        envelope = json.loads(row["envelope_json"] or "{}")
        if envelope.get("changeset_hash") != changeset["plan_hash"]:
            conn.execute("UPDATE agent_tasks SET state='INVALIDATED' WHERE id=?", (task_id,))
            conn.commit()
            raise HTTPException(status_code=409, detail="agent task ChangeSet hash no longer matches")
        expected = _agent_task_signature(envelope)
        if not hmac.compare_digest(str(row["signature"]), expected):
            raise HTTPException(status_code=409, detail="agent task signature verification failed")
        try:
            conn.execute("INSERT INTO agent_nonces (agent_id,nonce,seen_at) VALUES (?,?,?)", (agent["id"], payload.nonce, now))
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise HTTPException(status_code=409, detail="agent task claim nonce replay rejected") from exc
            raise
        changed = conn.execute("UPDATE agent_tasks SET state='CLAIMED',claim_nonce_hash=?,claimed_at=? WHERE id=? AND state='ISSUED'", (_hash_token(payload.nonce), now, task_id))
        if changed.rowcount != 1:
            raise HTTPException(status_code=409, detail="agent task was already claimed")
        db.audit(conn, "agent.task_claimed", agent["name"], "agent_task", task_id, {"claim_nonce_sha256": _hash_token(payload.nonce)})
        conn.commit()
        updated = conn.execute("SELECT * FROM agent_tasks WHERE id=?", (task_id,)).fetchone()
    return _agent_task_dict(updated)


@app.post("/v1/agents/tasks/{task_id}/result")
def complete_agent_task(task_id: str, payload: AgentTaskResult, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    now = int(time.time())
    _validate_credential_metadata(payload.evidence)
    with closing(db.connect()) as conn:
        agent = _authorized_agent(conn, authorization)
        row = conn.execute("SELECT * FROM agent_tasks WHERE id=? AND agent_id=?", (task_id, agent["id"])).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="agent task not found")
        if row["state"] != "CLAIMED":
            raise HTTPException(status_code=409, detail=f"agent task cannot complete from state {row['state']}")
        state = "SUCCEEDED" if payload.status == "SUCCEEDED" else "FAILED"
        result = {"status": payload.status, "summary": payload.summary, "evidence": payload.evidence, "completed_at": now}
        conn.execute("UPDATE agent_tasks SET state=?,completed_at=?,result_json=? WHERE id=?", (state, now, json.dumps(result, sort_keys=True), task_id))
        db.audit(conn, "agent.task_completed", agent["name"], "agent_task", task_id, {"status": payload.status, "summary": payload.summary})
        conn.commit()
        updated = conn.execute("SELECT * FROM agent_tasks WHERE id=?", (task_id,)).fetchone()
    return _agent_task_dict(updated)


@app.get("/v1/integrations")
def list_integrations() -> list[dict[str, Any]]:
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM integrations ORDER BY name").fetchall()
    return [_integration_dict(row) for row in rows]


@app.post("/v1/integrations", status_code=201)
def create_integration(payload: IntegrationCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    now = int(time.time())
    integration_id = f"int_{uuid.uuid4().hex[:16]}"
    with closing(db.connect()) as conn:
        env = _get_environment(conn, payload.environment_id)
        _get_credential_ref(conn, payload.credential_ref)
        try:
            conn.execute(
                """INSERT INTO integrations
                (id,name,kind,environment,endpoint,credential_ref,connection_mode,labels_json,status,created_at,updated_at,environment_id,allowed_scope_json,health_status)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (integration_id, payload.name, payload.kind, env["name"], payload.endpoint, payload.credential_ref, payload.connection_mode,
                 json.dumps(payload.labels, sort_keys=True), "configured", now, now, payload.environment_id,
                 json.dumps(payload.allowed_scope, sort_keys=True), "UNKNOWN"),
            )
            db.audit(conn, "integration.created", "admin", "integration", integration_id, {"kind": payload.kind, "environment_id": payload.environment_id})
            conn.commit()
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise HTTPException(status_code=409, detail="integration name already exists") from exc
            raise
        row = conn.execute("SELECT * FROM integrations WHERE id=?", (integration_id,)).fetchone()
    return _integration_dict(row)


@app.patch("/v1/integrations/{integration_id}")
def update_integration(integration_id: str, payload: IntegrationUpdate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="no fields supplied")
    with closing(db.connect()) as conn:
        if not conn.execute("SELECT 1 FROM integrations WHERE id=?", (integration_id,)).fetchone():
            raise HTTPException(status_code=404, detail="integration not found")
        if "environment_id" in updates:
            env = _get_environment(conn, updates["environment_id"])
            updates["environment"] = env["name"]
        if "credential_ref" in updates:
            _get_credential_ref(conn, updates["credential_ref"])
        if "labels" in updates:
            updates["labels_json"] = json.dumps(updates.pop("labels"), sort_keys=True)
        if "allowed_scope" in updates:
            updates["allowed_scope_json"] = json.dumps(updates.pop("allowed_scope"), sort_keys=True)
        updates["updated_at"] = int(time.time())
        fields = list(updates)
        conn.execute(f"UPDATE integrations SET {', '.join(f'{f}=?' for f in fields)} WHERE id=?", (*[updates[f] for f in fields], integration_id))
        db.audit(conn, "integration.updated", "admin", "integration", integration_id, {"fields": fields})
        conn.commit()
        row = conn.execute("SELECT * FROM integrations WHERE id=?", (integration_id,)).fetchone()
    return _integration_dict(row)


@app.delete("/v1/integrations/{integration_id}", status_code=204)
def delete_integration(integration_id: str, authorization: str | None = Header(default=None)) -> None:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        if conn.execute("SELECT 1 FROM targets WHERE integration_id=? LIMIT 1", (integration_id,)).fetchone():
            raise HTTPException(status_code=409, detail="integration has targets")
        cur = conn.execute("DELETE FROM integrations WHERE id=?", (integration_id,))
        if not cur.rowcount:
            raise HTTPException(status_code=404, detail="integration not found")
        db.audit(conn, "integration.deleted", "admin", "integration", integration_id)
        conn.commit()


@app.post("/v1/integrations/{integration_id}/health")
async def test_integration_health(integration_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        row = conn.execute("SELECT * FROM integrations WHERE id=?", (integration_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="integration not found")
        endpoint = row["endpoint"]
    if not endpoint:
        raise HTTPException(status_code=400, detail="integration has no endpoint")
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=400, detail="health testing currently supports only http/https endpoints")

    status = "UNHEALTHY"
    detail = "connection failed"
    code = None
    try:
        timeout = float(os.getenv("HERMES_HEALTH_TIMEOUT_SECONDS", "5"))
        if row["kind"] == "radar":
            if row["credential_ref"]:
                raise radar_provider.RadarProtocolError("direct Radar health does not accept credential material; use an internal no-auth/RBAC-scoped Radar endpoint")
            result = await radar_provider.health(endpoint, timeout=timeout)
            status = "HEALTHY" if result.get("ok") else "UNHEALTHY"
            detail = f"MCP {result.get('protocol_version', 'unknown')}"
        else:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
                response = await client.get(endpoint, headers={"User-Agent": f"hermes-control-plane/{VERSION}"})
                code = response.status_code
                status = "HEALTHY" if 200 <= code < 500 else "UNHEALTHY"
                detail = f"HTTP {code}"
    except Exception as exc:
        detail = f"{type(exc).__name__}: {str(exc)[:240]}"

    now = int(time.time())
    with closing(db.connect()) as conn:
        conn.execute("UPDATE integrations SET health_status=?,last_health_at=?,last_health_detail=?,updated_at=? WHERE id=?", (status, now, detail, now, integration_id))
        db.audit(conn, "integration.health", "admin", "integration", integration_id, {"status": status, "detail": detail, "http_status": code})
        conn.commit()
    return {"integration_id": integration_id, "status": status, "detail": detail, "http_status": code, "tested_at": now, "credential_used": False}


@app.get("/v1/providers")
def list_providers() -> list[dict[str, Any]]:
    return [{"id": provider_id, **spec} for provider_id, spec in sorted(PROVIDERS.items())]


@app.get("/v1/providers/{provider_id}")
def get_provider(provider_id: str) -> dict[str, Any]:
    item = provider_descriptor(provider_id)
    if not item:
        raise HTTPException(status_code=404, detail="provider not found")
    return item


@app.get("/v1/preflight/ssh/spec")
def ssh_preflight_spec() -> dict[str, Any]:
    return host_preflight.spec()


@app.get("/v1/servers")
def list_servers() -> list[dict[str, Any]]:
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM servers ORDER BY hostname").fetchall()
    return [_server_dict(row) for row in rows]


@app.get("/v1/servers/{server_id}")
def get_server(server_id: str) -> dict[str, Any]:
    with closing(db.connect()) as conn:
        row = _get_server(conn, server_id)
    return _server_dict(row)


@app.post("/v1/servers", status_code=201)
def create_server(payload: ServerCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    management_ip = _validated_ip(payload.management_ip, "management_ip")
    provisioning_ip = _validated_ip(payload.provisioning_ip, "provisioning_ip")
    bmc_ip = _validated_ip(payload.bmc_ip, "bmc_ip")
    host_fingerprint = _validate_host_fingerprint(payload.host_fingerprint)
    server_id = f"srv_{uuid.uuid4().hex[:16]}"
    now = int(time.time())
    with closing(db.connect()) as conn:
        _get_environment(conn, payload.environment_id)
        _validate_server_credentials(conn, payload.credential_ref, payload.bmc_credential_ref)
        _assert_server_ips_unique(conn, management_ip, provisioning_ip, bmc_ip)
        try:
            conn.execute(
                """INSERT INTO servers
                (id,hostname,environment_id,management_ip,provisioning_ip,bmc_ip,ssh_port,ssh_user,host_fingerprint,connection_mode,credential_ref,bmc_credential_ref,architecture,site,rack,zone,labels_json,status,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (server_id, payload.hostname, payload.environment_id, management_ip, provisioning_ip, bmc_ip,
                 payload.ssh_port, payload.ssh_user, host_fingerprint, payload.connection_mode, payload.credential_ref,
                 payload.bmc_credential_ref, payload.architecture, payload.site, payload.rack, payload.zone,
                 json.dumps(payload.labels, sort_keys=True), "configured", now, now),
            )
            db.audit(conn, "server.created", "admin", "server", server_id, {
                "hostname": payload.hostname, "management_ip": management_ip, "credential_ref": payload.credential_ref,
            })
            conn.commit()
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise HTTPException(status_code=409, detail="server hostname or IP is already registered") from exc
            raise
        row = _get_server(conn, server_id)
    return _server_dict(row)


@app.patch("/v1/servers/{server_id}")
def update_server(server_id: str, payload: ServerUpdate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="no fields supplied")
    with closing(db.connect()) as conn:
        current = _get_server(conn, server_id)
        if "environment_id" in updates:
            _get_environment(conn, updates["environment_id"])
        credential_ref = updates.get("credential_ref", current["credential_ref"])
        bmc_credential_ref = updates.get("bmc_credential_ref", current["bmc_credential_ref"])
        _validate_server_credentials(conn, credential_ref, bmc_credential_ref)
        for field in ("management_ip", "provisioning_ip", "bmc_ip"):
            if field in updates:
                updates[field] = _validated_ip(updates[field], field)
        if "host_fingerprint" in updates:
            updates["host_fingerprint"] = _validate_host_fingerprint(updates["host_fingerprint"])
        management_ip = updates.get("management_ip", current["management_ip"])
        provisioning_ip = updates.get("provisioning_ip", current["provisioning_ip"])
        bmc_ip = updates.get("bmc_ip", current["bmc_ip"])
        _assert_server_ips_unique(conn, management_ip, provisioning_ip, bmc_ip, exclude_id=server_id)
        if "labels" in updates:
            updates["labels_json"] = json.dumps(updates.pop("labels"), sort_keys=True)
        updates["updated_at"] = int(time.time())
        fields = list(updates)
        try:
            conn.execute(f"UPDATE servers SET {', '.join(f'{f}=?' for f in fields)} WHERE id=?", (*[updates[f] for f in fields], server_id))
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise HTTPException(status_code=409, detail="server hostname or IP is already registered") from exc
            raise
        db.audit(conn, "server.updated", "admin", "server", server_id, {"fields": fields})
        conn.commit()
        row = _get_server(conn, server_id)
    return _server_dict(row)


@app.delete("/v1/servers/{server_id}", status_code=204)
def delete_server(server_id: str, authorization: str | None = Header(default=None)) -> None:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        _get_server(conn, server_id)
        if conn.execute("SELECT 1 FROM changesets WHERE target_id=? AND state NOT IN ('REJECTED','CANCELLED','EXPIRED','EXECUTED','FAILED','POLICY_DENIED','PREVIEW_FAILED','STALE_POLICY') LIMIT 1", (server_id,)).fetchone():
            raise HTTPException(status_code=409, detail="server has active ChangeSets")
        if conn.execute("SELECT 1 FROM provider_jobs WHERE server_id=? AND state NOT IN ('SUCCEEDED','FAILED','CANCELLED') LIMIT 1", (server_id,)).fetchone():
            raise HTTPException(status_code=409, detail="server has active provider jobs")
        conn.execute("DELETE FROM provider_job_events WHERE job_id IN (SELECT id FROM provider_jobs WHERE server_id=?)", (server_id,))
        conn.execute("DELETE FROM provider_jobs WHERE server_id=?", (server_id,))
        conn.execute("DELETE FROM servers WHERE id=?", (server_id,))
        db.audit(conn, "server.deleted", "admin", "server", server_id)
        conn.commit()


@app.post("/v1/servers/{server_id}/preflight-plan", status_code=201)
def create_server_preflight_plan(server_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        server = _get_server(conn, server_id)
        if server["status"] != "configured":
            raise HTTPException(status_code=409, detail="server is disabled")
        _validate_server_credentials(conn, server["credential_ref"], server["bmc_credential_ref"])
        row = _insert_changeset(
            conn, operation="discover.ssh.preflight", adapter="ssh", target_id=server_id,
            requested_by="admin:preflight", source_channel="api", source_revision=None,
            parameters={"preflight_spec": host_preflight.spec(), "credential_ref": server["credential_ref"], "host_fingerprint": server["host_fingerprint"]},
            policy_generation=db.get_policy_generation(conn), ttl_seconds=900,
        )
        preview = {"summary": f"Read-only SSH preflight for {server['hostname']}", "details": {"checks": [x["id"] for x in host_preflight.CHECKS]}, "generated_at": int(time.time()), "source": "deterministic-preflight-planner"}
        conn.execute("UPDATE changesets SET preview_json=?,state='PREVIEWED',updated_at=? WHERE id=?", (json.dumps(preview, sort_keys=True), int(time.time()), row["id"]))
        job_id = f"job_{uuid.uuid4().hex[:16]}"
        conn.execute("INSERT INTO provider_jobs (id,provider_id,server_id,changeset_id,operation,state,stage,attempt,max_attempts,plan_hash,request_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (job_id, "ssh", server_id, row["id"], "discover.ssh.preflight", "READY", "discover", 1, 3, row["plan_hash"], json.dumps({"spec": host_preflight.spec()}, sort_keys=True), int(time.time()), int(time.time())))
        _provider_job_event(conn, job_id, "discover", "READY", "Deterministic SSH preflight plan is ready for constrained execution")
        db.audit(conn, "server.preflight_planned", "admin", "server", server_id, {"changeset_id": row["id"], "job_id": job_id, "plan_hash": row["plan_hash"]})
        conn.commit()
        updated = conn.execute("SELECT * FROM changesets WHERE id=?", (row["id"],)).fetchone()
    return {"changeset": _changeset_dict(updated), "provider_job_id": job_id, "capability": "ssh.preflight", "execution": "agent-task" if server["connection_mode"] == "agent" else "ssh-provider-worker"}


@app.post("/v1/servers/{server_id}/preflight-result")
def record_server_preflight_result(server_id: str, payload: ServerPreflightResult, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    # Results are metadata/facts only; raw credential-shaped evidence is rejected.
    _require_admin(authorization)
    _validate_credential_metadata(payload.facts)
    for check in payload.checks:
        _validate_credential_metadata(check)
    now = int(time.time())
    body = payload.model_dump()
    with closing(db.connect()) as conn:
        _get_server(conn, server_id)
        job = conn.execute("SELECT * FROM provider_jobs WHERE id=?", (payload.provider_job_id,)).fetchone()
        if not job or job["server_id"] != server_id or job["operation"] != "discover.ssh.preflight":
            raise HTTPException(status_code=409, detail="preflight result must reference this server's SSH preflight provider job")
        _provider_job_authorization(conn, job)
        if job["state"] not in {"READY", "RUNNING"}:
            raise HTTPException(status_code=409, detail=f"preflight provider job cannot complete from state {job['state']}")
        job_state = "FAILED" if payload.status == "FAIL" else "SUCCEEDED"
        conn.execute("UPDATE provider_jobs SET state=?,stage='verify',result_json=?,updated_at=? WHERE id=?",
                     (job_state, json.dumps(body, sort_keys=True), now, payload.provider_job_id))
        _provider_job_event(conn, payload.provider_job_id, "verify", payload.status, payload.summary, {"checks": payload.checks, "facts": payload.facts})
        conn.execute("UPDATE servers SET preflight_status=?,preflight_json=?,inventory_json=?,discovery_status=?,last_preflight_at=?,updated_at=? WHERE id=?",
                     (payload.status, json.dumps(body, sort_keys=True), json.dumps(payload.facts, sort_keys=True), "DISCOVERED" if payload.status != "FAIL" else "FAILED", now, now, server_id))
        db.audit(conn, "server.preflight_recorded", "admin", "server", server_id, {"status": payload.status, "summary": payload.summary, "provider_job_id": payload.provider_job_id})
        conn.commit()
        row = _get_server(conn, server_id)
    return _server_dict(row)


@app.post("/v1/servers/{server_id}/bootstrap-plan", status_code=201)
def create_bootstrap_plan(server_id: str, payload: BootstrapPlanCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_bot(authorization)
    _require_bot_origin(payload.source_channel)
    provider = provider_descriptor(payload.provider)
    if not provider or provider.get("kind") != "cluster-bootstrap":
        raise HTTPException(status_code=422, detail="unsupported bootstrap provider")
    with closing(db.connect()) as conn:
        server = _get_server(conn, server_id)
        if server["status"] != "configured":
            raise HTTPException(status_code=409, detail="server is disabled")
        _validate_server_credentials(conn, server["credential_ref"], server["bmc_credential_ref"])
        if server["preflight_status"] != "PASS":
            raise HTTPException(status_code=409, detail="server must have PASS preflight status before bootstrap planning")
        params = {
            "provider": payload.provider,
            "cluster_name": payload.cluster_name,
            "kubernetes_version": payload.kubernetes_version,
            "node_role": payload.node_role,
            "network_plugin": payload.network_plugin,
            "hubble_enabled": payload.hubble_enabled,
            "radar_enabled": payload.radar_enabled,
            "server_id": server_id,
            "credential_ref": server["credential_ref"],
            "provider_parameters": payload.parameters,
            "lifecycle": provider["lifecycle"],
        }
        row = _insert_changeset(
            conn, operation="bootstrap.apply", adapter="bootstrap", target_id=server_id,
            requested_by=payload.requested_by, source_channel=payload.source_channel, source_revision=None,
            parameters=params, policy_generation=db.get_policy_generation(conn), ttl_seconds=payload.ttl_seconds,
        )
        preview = {
            "summary": f"Bootstrap {payload.cluster_name} on {server['hostname']} with {payload.provider}",
            "details": {"provider": payload.provider, "stages": provider["lifecycle"], "radar": payload.radar_enabled, "hubble": payload.hubble_enabled, "mutation_gate": "ChangeSet approval required"},
            "generated_at": int(time.time()), "source": "deterministic-bootstrap-planner",
        }
        conn.execute("UPDATE changesets SET preview_json=?,state='PREVIEWED',updated_at=? WHERE id=?", (json.dumps(preview, sort_keys=True), int(time.time()), row["id"]))
        job_id = f"job_{uuid.uuid4().hex[:16]}"
        now = int(time.time())
        conn.execute("INSERT INTO provider_jobs (id,provider_id,server_id,changeset_id,operation,state,stage,attempt,max_attempts,plan_hash,request_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (job_id, payload.provider, server_id, row["id"], "bootstrap.apply", "WAITING_APPROVAL", "plan", 1, 3, row["plan_hash"], json.dumps(params, sort_keys=True), now, now))
        _provider_job_event(conn, job_id, "plan", "WAITING_APPROVAL", "Bootstrap job is blocked on the bound ChangeSet approval")
        db.audit(conn, "bootstrap.planned", payload.requested_by, "provider_job", job_id, {"changeset_id": row["id"], "provider": payload.provider, "plan_hash": row["plan_hash"]})
        conn.commit()
        updated = conn.execute("SELECT * FROM changesets WHERE id=?", (row["id"],)).fetchone()
    return {"changeset": _changeset_dict(updated), "provider_job_id": job_id, "provider": provider, "execution": "blocked-until-approved-agent-task"}


@app.get("/v1/provider-jobs")
def list_provider_jobs(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM provider_jobs ORDER BY created_at DESC,id DESC").fetchall()
    return [_provider_job_dict(row) for row in rows]


@app.post("/v1/provider-jobs/{job_id}/authorize")
def authorize_provider_job(job_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_bot(authorization)
    now = int(time.time())
    with closing(db.connect()) as conn:
        job = conn.execute("SELECT * FROM provider_jobs WHERE id=?", (job_id,)).fetchone()
        if not job:
            raise HTTPException(status_code=404, detail="provider job not found")
        if job["state"] != "WAITING_APPROVAL":
            raise HTTPException(status_code=409, detail="provider job is not waiting for approval")
        changeset = _provider_job_authorization(conn, job)
        ticket = None
        signature = None
        approval_ids: list[str] = []
        if job["operation"] == "cluster.provision.apply":
            ticket, signature, approval_ids = _issue_provider_job_ticket(conn, job, changeset)
        conn.execute("UPDATE provider_jobs SET state='READY',stage='authorized',updated_at=? WHERE id=?", (now, job_id))
        _provider_job_event(conn, job_id, "authorized", "AUTHORIZED", "Exact approved ChangeSet hash authorized provider job", {"approval_count": len(approval_ids), "trusted_runtime": job["operation"] == "cluster.provision.apply"})
        audit_payload = {"changeset_id": changeset["id"], "plan_hash": job["plan_hash"], "executor": "cluster-provider-worker" if job["operation"] == "cluster.provision.apply" else "legacy-provider-job"}
        if ticket is not None:
            audit_payload["ticket_hash"] = sha256_hex(ticket)
        db.audit(conn, "provider_job.authorized", "hermes-bot", "provider_job", job_id, audit_payload)
        conn.commit()
        job = conn.execute("SELECT * FROM provider_jobs WHERE id=?", (job_id,)).fetchone()
    response = _provider_job_dict(job)
    if ticket is not None and signature is not None:
        response.update(execution_ticket=ticket, signature=signature)
    return response


@app.post("/v1/provider-jobs/{job_id}/execute")
async def execute_provider_job(job_id: str, payload: OperationJobExecute, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_bot(authorization)
    with closing(db.connect()) as conn:
        job = conn.execute("SELECT * FROM provider_jobs WHERE id=?", (job_id,)).fetchone()
        if not job:
            raise HTTPException(status_code=404, detail="provider job not found")
        if job["state"] != "READY":
            raise HTTPException(status_code=409, detail="provider job must be READY before trusted execution")
        if job["operation"] != "cluster.provision.apply":
            raise HTTPException(status_code=422, detail="legacy/bootstrap provider job has no trusted cluster-provider runtime path")
        changeset, _, typed_plan, approval_ids = _verify_provider_job_ticket(conn, job, payload.execution_ticket, payload.signature)
        now = int(time.time())
        if approval_ids:
            placeholders = ",".join("?" for _ in approval_ids)
            changed = conn.execute(
                f"UPDATE approvals SET status='CONSUMED',consumed_at=?,decided_at=? WHERE id IN ({placeholders}) AND status='APPROVED' AND consumed_at IS NULL",
                (now, now, *approval_ids),
            )
            if changed.rowcount != len(approval_ids):
                raise HTTPException(status_code=409, detail="provider approval consumption race detected")
        conn.execute("UPDATE provider_jobs SET state='RUNNING',stage='execute',updated_at=? WHERE id=?", (now, job_id))
        conn.execute("UPDATE changesets SET state='EXECUTING',updated_at=? WHERE id=?", (now, changeset["id"]))
        request = json.loads(job["request_json"] or "{}")
        run = conn.execute("SELECT id FROM provisioning_runs WHERE changeset_id=?", (changeset["id"],)).fetchone()
        if run:
            conn.execute("UPDATE provisioning_runs SET state='RUNNING',stage='apply',updated_at=? WHERE id=?", (now, run["id"]))
            conn.execute("UPDATE clusters SET state='PROVISIONING',updated_at=? WHERE id=?", (now, request.get("cluster_id") or changeset["target_id"]))
        db.audit(conn, "provider_job.runtime_started", payload.actor, "provider_job", job_id, {"changeset_id": changeset["id"], "typed_plan_hash": typed_plan.get("plan_hash")})
        conn.commit()

    try:
        runtime_result = await provider_worker.post("/v1/provider/execute", {"ticket": payload.execution_ticket, "signature": payload.signature})
        _validate_credential_metadata(runtime_result)
    except HTTPException as exc:
        now = int(time.time())
        with closing(db.connect()) as conn:
            job = conn.execute("SELECT * FROM provider_jobs WHERE id=?", (job_id,)).fetchone()
            if job:
                changeset = _changeset(conn, job["changeset_id"])
                error = {"type": "cluster-provider-worker-error", "status_code": exc.status_code, "detail": exc.detail}
                conn.execute("UPDATE provider_jobs SET state='FAILED',stage='execute',result_json=?,updated_at=? WHERE id=?", (json.dumps(error, sort_keys=True), now, job_id))
                conn.execute("UPDATE changesets SET state='FAILED',execution_json=?,executed_at=?,updated_at=? WHERE id=?", (json.dumps(error, sort_keys=True), now, now, changeset["id"]))
                run = conn.execute("SELECT id,cluster_id FROM provisioning_runs WHERE changeset_id=?", (changeset["id"],)).fetchone()
                if run:
                    conn.execute("UPDATE provisioning_runs SET state='FAILED',stage='verify',result_json=?,updated_at=? WHERE id=?", (json.dumps(error, sort_keys=True), now, run["id"]))
                    conn.execute("UPDATE clusters SET state='ERROR',updated_at=? WHERE id=?", (now, run["cluster_id"]))
                _provider_job_event(conn, job_id, "execute", "FAILED", "Trusted provider runtime failed without returning raw stderr", {"error_type": "provider-runtime"})
                db.audit(conn, "provider_job.runtime_failed", payload.actor, "provider_job", job_id, {"changeset_id": changeset["id"], "error_type": "runtime"})
                conn.commit()
        raise

    now = int(time.time())
    with closing(db.connect()) as conn:
        job = conn.execute("SELECT * FROM provider_jobs WHERE id=?", (job_id,)).fetchone()
        if not job:
            raise HTTPException(status_code=409, detail="provider job disappeared during execution")
        changeset = _changeset(conn, job["changeset_id"])
        verification = _persist_provider_job_verification(conn, job=job, changeset=changeset, runtime_result=runtime_result, actor=payload.actor)
        final_state = "SUCCEEDED" if verification["status"] == "PASS" else "FAILED"
        result = {"state": final_state, "stage": "verify", "runtime_result": runtime_result, "verification_id": verification["id"], "completed_at": now}
        conn.execute("UPDATE provider_jobs SET state=?,stage='verify',result_json=?,updated_at=? WHERE id=?", (final_state, json.dumps(result, sort_keys=True), now, job_id))
        conn.execute("UPDATE changesets SET state=?,execution_json=?,executed_at=?,updated_at=? WHERE id=?", ("EXECUTED" if final_state == "SUCCEEDED" else "FAILED", json.dumps(runtime_result, sort_keys=True), now, now, changeset["id"]))
        run = conn.execute("SELECT id,cluster_id FROM provisioning_runs WHERE changeset_id=?", (changeset["id"],)).fetchone()
        if run:
            conn.execute("UPDATE provisioning_runs SET state=?,stage='verify',result_json=?,updated_at=? WHERE id=?", (final_state, json.dumps({"provider_job_states": {job_id: final_state}, "verification_id": verification["id"]}, sort_keys=True), now, run["id"]))
            conn.execute("UPDATE clusters SET state=?,updated_at=? WHERE id=?", ("READY" if final_state == "SUCCEEDED" else "ERROR", now, run["cluster_id"]))
        _provider_job_event(conn, job_id, "verify", final_state, "Trusted provider runtime completed with typed active verification", {"verification_id": verification["id"], "verification_status": verification["status"]})
        db.audit(conn, "provider_job.runtime_completed", payload.actor, "provider_job", job_id, {"changeset_id": changeset["id"], "verification_id": verification["id"], "verification_status": verification["status"]})
        conn.commit()
        updated = conn.execute("SELECT * FROM provider_jobs WHERE id=?", (job_id,)).fetchone()
    return {"provider_job": _provider_job_dict(updated), "verification": verification, "runtime_result": runtime_result}


@app.get("/v1/provider-jobs/{job_id}")
def get_provider_job(job_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        row = conn.execute("SELECT * FROM provider_jobs WHERE id=?", (job_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="provider job not found")
    return _provider_job_dict(row)


@app.get("/v1/provider-jobs/{job_id}/events")
def list_provider_job_events(job_id: str, after_id: int = Query(default=0, ge=0), authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        if not conn.execute("SELECT 1 FROM provider_jobs WHERE id=?", (job_id,)).fetchone():
            raise HTTPException(status_code=404, detail="provider job not found")
        rows = conn.execute("SELECT * FROM provider_job_events WHERE job_id=? AND id>? ORDER BY id", (job_id, after_id)).fetchall()
    return [{**dict(row), "evidence": json.loads(row["evidence_json"] or "{}"), "evidence_json": None} for row in rows]


@app.post("/v1/provider-jobs/{job_id}/transition")
def transition_provider_job(job_id: str, payload: ProviderJobTransition, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_bot(authorization)
    _validate_credential_metadata(payload.evidence)
    allowed = {
        "READY": {"RUNNING", "FAILED"},
        "RUNNING": {"RUNNING", "PAUSED", "SUCCEEDED", "FAILED"},
        "PAUSED": set(),
        "WAITING_APPROVAL": set(),
        "FAILED": set(),
        "SUCCEEDED": set(),
        "CANCELLED": set(),
    }
    with closing(db.connect()) as conn:
        job = conn.execute("SELECT * FROM provider_jobs WHERE id=?", (job_id,)).fetchone()
        if not job:
            raise HTTPException(status_code=404, detail="provider job not found")
        _provider_job_authorization(conn, job)
        if payload.state not in allowed.get(job["state"], set()):
            raise HTTPException(status_code=409, detail=f"provider job cannot transition from {job['state']} to {payload.state}")
        now = int(time.time())
        result_json = job["result_json"]
        if payload.state in {"SUCCEEDED", "FAILED"}:
            result_json = json.dumps({"state": payload.state, "stage": payload.stage, "message": payload.message, "evidence": payload.evidence, "completed_at": now}, sort_keys=True)
        conn.execute("UPDATE provider_jobs SET state=?,stage=?,result_json=?,updated_at=? WHERE id=?", (payload.state, payload.stage, result_json, now, job_id))
        _provider_job_event(conn, job_id, payload.stage, payload.state, payload.message, payload.evidence)
        db.audit(conn, "provider_job.transitioned", "hermes-bot", "provider_job", job_id, {"from": job["state"], "to": payload.state, "stage": payload.stage, "attempt": int(job["attempt"])})
        conn.commit()
        updated = conn.execute("SELECT * FROM provider_jobs WHERE id=?", (job_id,)).fetchone()
    return _provider_job_dict(updated)


def _retry_or_resume_provider_job(job_id: str, payload: ProviderJobRetry, authorization: str | None, *, resume: bool) -> dict[str, Any]:
    _require_bot(authorization)
    with closing(db.connect()) as conn:
        job = conn.execute("SELECT * FROM provider_jobs WHERE id=?", (job_id,)).fetchone()
        if not job:
            raise HTTPException(status_code=404, detail="provider job not found")
        expected = "PAUSED" if resume else "FAILED"
        if job["state"] != expected:
            raise HTTPException(status_code=409, detail=f"provider job must be {expected} to {'resume' if resume else 'retry'}")
        _provider_job_authorization(conn, job)
        attempt = int(job["attempt"]) if resume else int(job["attempt"]) + 1
        if attempt > int(job["max_attempts"]):
            raise HTTPException(status_code=409, detail="provider job retry limit reached")
        now = int(time.time())
        conn.execute("UPDATE provider_jobs SET state='READY',attempt=?,result_json=NULL,updated_at=? WHERE id=?", (attempt, now, job_id))
        status = "RESUMED" if resume else "RETRY"
        _provider_job_event(conn, job_id, job["stage"], status, payload.reason, {"attempt": attempt})
        db.audit(conn, f"provider_job.{status.lower()}", "hermes-bot", "provider_job", job_id, {"attempt": attempt, "reason": payload.reason})
        conn.commit()
        updated = conn.execute("SELECT * FROM provider_jobs WHERE id=?", (job_id,)).fetchone()
    return _provider_job_dict(updated)


@app.post("/v1/provider-jobs/{job_id}/retry")
def retry_provider_job(job_id: str, payload: ProviderJobRetry, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    return _retry_or_resume_provider_job(job_id, payload, authorization, resume=False)


@app.post("/v1/provider-jobs/{job_id}/resume")
def resume_provider_job(job_id: str, payload: ProviderJobRetry, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    return _retry_or_resume_provider_job(job_id, payload, authorization, resume=True)


@app.get("/v1/provider-jobs/{job_id}/stream")
async def stream_provider_job(job_id: str, request: Request, after_id: int = Query(default=0, ge=0), authorization: str | None = Header(default=None)):
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        if not conn.execute("SELECT 1 FROM provider_jobs WHERE id=?", (job_id,)).fetchone():
            raise HTTPException(status_code=404, detail="provider job not found")

    async def event_stream():
        cursor = after_id
        while True:
            if await request.is_disconnected():
                return
            with closing(db.connect()) as conn:
                rows = conn.execute("SELECT * FROM provider_job_events WHERE job_id=? AND id>? ORDER BY id", (job_id, cursor)).fetchall()
                job = conn.execute("SELECT state,stage,attempt,updated_at FROM provider_jobs WHERE id=?", (job_id,)).fetchone()
            for row in rows:
                cursor = int(row["id"])
                event = {**dict(row), "evidence": json.loads(row["evidence_json"] or "{}")}
                event.pop("evidence_json", None)
                yield f"id: {cursor}\nevent: provider-job\ndata: {json.dumps(event, sort_keys=True)}\n\n"
            if job and job["state"] in {"SUCCEEDED", "FAILED", "CANCELLED"}:
                yield f"event: end\ndata: {json.dumps(dict(job), sort_keys=True)}\n\n"
                return
            if not rows:
                yield ": heartbeat\n\n"
            await asyncio.sleep(1.0)

    return StreamingResponse(event_stream(), media_type="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


@app.get("/v1/targets")
def list_targets() -> list[dict[str, Any]]:
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM targets ORDER BY name").fetchall()
    return [_target_dict(row) for row in rows]


@app.post("/v1/targets", status_code=201)
def create_target(payload: TargetCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    target_id = f"tgt_{uuid.uuid4().hex[:16]}"
    now = int(time.time())
    with closing(db.connect()) as conn:
        _get_environment(conn, payload.environment_id)
        _get_credential_ref(conn, payload.credential_ref)
        if payload.integration_id and not conn.execute("SELECT 1 FROM integrations WHERE id=?", (payload.integration_id,)).fetchone():
            raise HTTPException(status_code=404, detail="integration not found")
        try:
            conn.execute(
                """INSERT INTO targets
                (id,name,kind,environment_id,integration_id,credential_ref,connection_mode,address,scope_json,labels_json,status,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (target_id, payload.name, payload.kind, payload.environment_id, payload.integration_id, payload.credential_ref,
                 payload.connection_mode, payload.address, json.dumps(payload.scope, sort_keys=True), json.dumps(payload.labels, sort_keys=True),
                 "configured", now, now),
            )
            db.audit(conn, "target.created", "admin", "target", target_id, {"kind": payload.kind, "environment_id": payload.environment_id})
            conn.commit()
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise HTTPException(status_code=409, detail="target name already exists") from exc
            raise
        row = conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
    return _target_dict(row)


@app.patch("/v1/targets/{target_id}")
def update_target(target_id: str, payload: TargetUpdate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="no fields supplied")
    with closing(db.connect()) as conn:
        if not conn.execute("SELECT 1 FROM targets WHERE id=?", (target_id,)).fetchone():
            raise HTTPException(status_code=404, detail="target not found")
        if "environment_id" in updates:
            _get_environment(conn, updates["environment_id"])
        if "credential_ref" in updates:
            _get_credential_ref(conn, updates["credential_ref"])
        if "integration_id" in updates and updates["integration_id"] and not conn.execute("SELECT 1 FROM integrations WHERE id=?", (updates["integration_id"],)).fetchone():
            raise HTTPException(status_code=404, detail="integration not found")
        if "scope" in updates:
            updates["scope_json"] = json.dumps(updates.pop("scope"), sort_keys=True)
        if "labels" in updates:
            updates["labels_json"] = json.dumps(updates.pop("labels"), sort_keys=True)
        updates["updated_at"] = int(time.time())
        fields = list(updates)
        conn.execute(f"UPDATE targets SET {', '.join(f'{f}=?' for f in fields)} WHERE id=?", (*[updates[f] for f in fields], target_id))
        db.audit(conn, "target.updated", "admin", "target", target_id, {"fields": fields})
        conn.commit()
        row = conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
    return _target_dict(row)


@app.delete("/v1/targets/{target_id}", status_code=204)
def delete_target(target_id: str, authorization: str | None = Header(default=None)) -> None:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        if conn.execute(
            "SELECT 1 FROM changesets WHERE target_id=? AND state NOT IN ('REJECTED','CANCELLED','EXPIRED','EXECUTED','FAILED','POLICY_DENIED','PREVIEW_FAILED') LIMIT 1",
            (target_id,),
        ).fetchone():
            raise HTTPException(status_code=409, detail="target has active ChangeSets")
        if conn.execute("SELECT 1 FROM applications WHERE target_id=? LIMIT 1", (target_id,)).fetchone():
            raise HTTPException(status_code=409, detail="target has applications")
        cur = conn.execute("DELETE FROM targets WHERE id=?", (target_id,))
        if not cur.rowcount:
            raise HTTPException(status_code=404, detail="target not found")
        db.audit(conn, "target.deleted", "admin", "target", target_id)
        conn.commit()


@app.get("/v1/applications")
def list_applications() -> list[dict[str, Any]]:
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM applications ORDER BY name").fetchall()
    return [_application_dict(row) for row in rows]


@app.post("/v1/applications", status_code=201)
def create_application(payload: ApplicationCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    now = int(time.time())
    application_id = f"app_{uuid.uuid4().hex[:16]}"
    with closing(db.connect()) as conn:
        _get_environment(conn, payload.environment_id)
        target = conn.execute("SELECT * FROM targets WHERE id=?", (payload.target_id,)).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="target not found")
        if target["environment_id"] != payload.environment_id:
            raise HTTPException(status_code=409, detail="application environment must match target environment")
        try:
            conn.execute(
                """INSERT INTO applications
                (id,name,environment_id,target_id,source_repository,revision_policy,build_context,image_repository,deployment_type,values_files_json,verification_checks_json,rollback_strategy_json,labels_json,status,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (application_id, payload.name, payload.environment_id, payload.target_id, payload.source_repository, payload.revision_policy, payload.build_context, payload.image_repository, payload.deployment_type, json.dumps(payload.values_files, sort_keys=True), json.dumps(payload.verification_checks, sort_keys=True), json.dumps(payload.rollback_strategy, sort_keys=True), json.dumps(payload.labels, sort_keys=True), "configured", now, now),
            )
            db.audit(conn, "application.created", "admin", "application", application_id, {"deployment_type": payload.deployment_type, "target_id": payload.target_id, "source_repository": payload.source_repository})
            conn.commit()
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise HTTPException(status_code=409, detail="application name already exists") from exc
            raise
        row = conn.execute("SELECT * FROM applications WHERE id=?", (application_id,)).fetchone()
    return _application_dict(row)


@app.patch("/v1/applications/{application_id}")
def update_application(application_id: str, payload: ApplicationUpdate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="no fields supplied")
    with closing(db.connect()) as conn:
        current = conn.execute("SELECT * FROM applications WHERE id=?", (application_id,)).fetchone()
        if not current:
            raise HTTPException(status_code=404, detail="application not found")
        environment_id = updates.get("environment_id", current["environment_id"])
        target_id = updates.get("target_id", current["target_id"])
        _get_environment(conn, environment_id)
        target = conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="target not found")
        if target["environment_id"] != environment_id:
            raise HTTPException(status_code=409, detail="application environment must match target environment")
        json_fields = {"values_files": "values_files_json", "verification_checks": "verification_checks_json", "rollback_strategy": "rollback_strategy_json", "labels": "labels_json"}
        for source, dest in json_fields.items():
            if source in updates:
                updates[dest] = json.dumps(updates.pop(source), sort_keys=True)
        updates["updated_at"] = int(time.time())
        fields = list(updates)
        conn.execute(f"UPDATE applications SET {', '.join(f'{field}=?' for field in fields)} WHERE id=?", (*[updates[field] for field in fields], application_id))
        db.audit(conn, "application.updated", "admin", "application", application_id, {"fields": fields})
        conn.commit()
        row = conn.execute("SELECT * FROM applications WHERE id=?", (application_id,)).fetchone()
    return _application_dict(row)


@app.delete("/v1/applications/{application_id}", status_code=204)
def delete_application(application_id: str, authorization: str | None = Header(default=None)) -> None:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        cur = conn.execute("DELETE FROM applications WHERE id=?", (application_id,))
        if not cur.rowcount:
            raise HTTPException(status_code=404, detail="application not found")
        db.audit(conn, "application.deleted", "admin", "application", application_id)
        conn.commit()


@app.get("/v1/changesets")
def list_changesets(limit: int = Query(default=200, ge=1, le=1000)) -> list[dict[str, Any]]:
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM changesets ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [_changeset_dict(row) for row in rows]


@app.get("/v1/changesets/{changeset_id}")
def get_changeset(changeset_id: str) -> dict[str, Any]:
    with closing(db.connect()) as conn:
        row = _changeset(conn, changeset_id)
    return _changeset_dict(row)


def _require_current_policy_generation(conn, row: Any) -> int:
    current = db.get_policy_generation(conn)
    stored = int(row["policy_generation"] or 1)
    if stored != current:
        raise HTTPException(status_code=409, detail=f"ChangeSet policy generation {stored} is stale; current generation is {current}")
    return current


def _insert_changeset(
    conn,
    *,
    operation: str,
    adapter: str,
    target_id: str,
    requested_by: str,
    source_channel: str,
    source_revision: str | None,
    parameters: dict[str, Any],
    policy_generation: int,
    ttl_seconds: int,
) -> Any:
    created_at = int(time.time())
    expires_at = created_at + ttl_seconds
    changeset_id = f"chg_{uuid.uuid4().hex[:16]}"
    risk = classify(operation)
    target_snapshot = _target_snapshot(conn, target_id)
    if target_snapshot["status"] != "configured":
        raise HTTPException(status_code=409, detail="target is disabled")
    plan = {
        "schema_version": 2,
        "operation": operation,
        "adapter": adapter,
        "target_id": target_id,
        "source_revision": source_revision,
        "parameters": parameters,
        "policy_generation": policy_generation,
        "target_snapshot": target_snapshot,
    }
    plan_json = canonical_json(plan)
    plan_hash = sha256_hex(plan)
    conn.execute(
        """INSERT INTO changesets
        (id,operation,target_id,requested_by,source_channel,risk,parameters_json,content_hash,state,created_at,adapter,source_revision,plan_json,plan_hash,preview_json,approval_required,policy_generation,expires_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (changeset_id, operation, target_id, requested_by, source_channel, risk,
         json.dumps(parameters, sort_keys=True), plan_hash, "PLANNED", created_at, adapter, source_revision,
         plan_json, plan_hash, None, int(approval_required(risk)), policy_generation, expires_at, created_at),
    )
    db.audit(conn, "changeset.created", requested_by, "changeset", changeset_id, {"plan_hash": plan_hash, "risk": risk})
    return conn.execute("SELECT * FROM changesets WHERE id=?", (changeset_id,)).fetchone()


@app.post("/v1/changesets", status_code=201)
def create_changeset(payload: ChangeSetCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    if _is_infra_mutation(payload.adapter, payload.operation):
        _require_bot(authorization)
        _require_bot_origin(payload.source_channel)
    else:
        _require_admin(authorization)
    with closing(db.connect()) as conn:
        row = _insert_changeset(
            conn,
            operation=payload.operation,
            adapter=payload.adapter,
            target_id=payload.target_id,
            requested_by=payload.requested_by,
            source_channel=payload.source_channel,
            source_revision=payload.source_revision,
            parameters=payload.parameters,
            policy_generation=db.get_policy_generation(conn),
            ttl_seconds=payload.ttl_seconds,
        )
        conn.commit()
    return _changeset_dict(row)


@app.post("/v1/changesets/{changeset_id}/rollback-plan", status_code=201)
def create_rollback_plan(
    changeset_id: str,
    payload: RollbackPlanCreate,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_bot(authorization)
    _require_bot_origin(payload.source_channel)
    with closing(db.connect()) as conn:
        source = _changeset(conn, changeset_id)
        if source["state"] != "EXECUTED":
            raise HTTPException(status_code=409, detail="rollback can only be generated from an EXECUTED ChangeSet")
        execution = json.loads(source["execution_json"] or "null") or {}
        original = json.loads(source["plan_json"] or "{}")
        original_params = original.get("parameters") or {}
        operation = str(source["operation"] or "")

        if operation in {"kubernetes.manifest.apply", "kubernetes.manifest.delete", "kubernetes.manifest.rollback"}:
            before_state = execution.get("before_state")
            if not isinstance(before_state, dict) or not before_state.get("resources"):
                raise HTTPException(status_code=409, detail="executed ChangeSet has no captured Kubernetes before-state")
            actions = []
            for item in before_state.get("resources") or []:
                ref = item.get("resource") or {}
                if item.get("exists"):
                    manifest = item.get("manifest")
                    if not manifest:
                        raise HTTPException(status_code=409, detail="captured rollback state is incomplete")
                    actions.append({"action": "apply", "resource": ref, "manifest": manifest})
                else:
                    actions.append({"action": "delete", "resource": ref})
            rb_operation = "kubernetes.manifest.rollback"
            rb_adapter = "kubernetes"
            rb_params = {
                "namespace": original_params.get("namespace", "default"),
                "source_changeset_id": changeset_id,
                "actions": actions,
            }
        elif operation in {"helm.install", "helm.upgrade", "helm.rollback"}:
            before = execution.get("before_release") or {}
            release = original_params.get("release")
            namespace = original_params.get("namespace", "default")
            if before.get("exists") and int(before.get("revision") or 0) >= 1:
                rb_operation = "helm.rollback"
                rb_adapter = "helm"
                rb_params = {
                    "release": release,
                    "namespace": namespace,
                    "revision": int(before["revision"]),
                    "source_changeset_id": changeset_id,
                }
            elif not before.get("exists"):
                rb_operation = "helm.uninstall"
                rb_adapter = "helm"
                rb_params = {
                    "release": release,
                    "namespace": namespace,
                    "source_changeset_id": changeset_id,
                }
            else:
                raise HTTPException(status_code=409, detail="executed Helm ChangeSet has no usable previous release revision")
        else:
            raise HTTPException(status_code=422, detail=f"rollback is not implemented for {operation}")

        row = _insert_changeset(
            conn,
            operation=rb_operation,
            adapter=rb_adapter,
            target_id=source["target_id"],
            requested_by=payload.requested_by,
            source_channel=payload.source_channel,
            source_revision=None,
            parameters=rb_params,
            policy_generation=db.get_policy_generation(conn),
            ttl_seconds=payload.ttl_seconds,
        )
        db.audit(conn, "changeset.rollback_planned", payload.requested_by, "changeset", row["id"], {
            "source_changeset_id": changeset_id,
            "plan_hash": row["plan_hash"],
        })
        conn.commit()
    return _changeset_dict(row)


@app.post("/v1/changesets/{changeset_id}/preview")
def preview_changeset(changeset_id: str, payload: PreviewCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    now = int(time.time())
    with closing(db.connect()) as conn:
        row = _changeset(conn, changeset_id)
        _require_infra_actor(row, authorization)
        _require_current_policy_generation(conn, row)
        if row["state"] not in {"PLANNED", "PREVIEWED"}:
            raise HTTPException(status_code=409, detail=f"cannot preview ChangeSet in state {row['state']}")
        preview = {"summary": payload.summary, "details": payload.details, "generated_at": now, "source": "planner"}
        conn.execute("UPDATE changesets SET preview_json=?,state='PREVIEWED',updated_at=? WHERE id=?", (json.dumps(preview, sort_keys=True), now, changeset_id))
        db.audit(conn, "changeset.previewed", "planner", "changeset", changeset_id, {"plan_hash": row["plan_hash"]})
        conn.commit()
        updated = conn.execute("SELECT * FROM changesets WHERE id=?", (changeset_id,)).fetchone()
    return _changeset_dict(updated)


@app.post("/v1/changesets/{changeset_id}/request-approval")
def request_approval(changeset_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    now = int(time.time())
    with closing(db.connect()) as conn:
        row = _changeset(conn, changeset_id)
        _require_infra_actor(row, authorization)
        _require_current_policy_generation(conn, row)
        if not row["approval_required"]:
            raise HTTPException(status_code=409, detail="risk engine does not require approval for this ChangeSet")
        if row["state"] != "PREVIEWED":
            raise HTTPException(status_code=409, detail="ChangeSet must be PREVIEWED before approval is requested")
        conn.execute("UPDATE changesets SET state='AWAITING_APPROVAL',updated_at=? WHERE id=?", (now, changeset_id))
        db.audit(conn, "changeset.approval_requested", row["requested_by"], "changeset", changeset_id, {"plan_hash": row["plan_hash"], "risk": row["risk"]})
        conn.commit()
        updated = conn.execute("SELECT * FROM changesets WHERE id=?", (changeset_id,)).fetchone()
    return _changeset_dict(updated)


@app.post("/v1/changesets/{changeset_id}/approve", status_code=201)
def approve_changeset(changeset_id: str, payload: ApprovalDecision, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    now = int(time.time())
    with closing(db.connect()) as conn:
        row = _changeset(conn, changeset_id)
        if _is_infra_mutation(row["adapter"], row["operation"]):
            _require_approval_bot(authorization)
        else:
            _require_admin(authorization)
        _require_current_policy_generation(conn, row)
        if row["state"] != "AWAITING_APPROVAL":
            raise HTTPException(status_code=409, detail="ChangeSet is not awaiting approval")
        if payload.plan_hash != row["plan_hash"]:
            raise HTTPException(status_code=409, detail="approval hash does not match current ChangeSet plan")
        if row["risk"] in {"HIGH", "CRITICAL"} and payload.approver == row["requested_by"]:
            raise HTTPException(status_code=403, detail="requester cannot self-approve HIGH/CRITICAL ChangeSets")
        if conn.execute(
            "SELECT 1 FROM approvals WHERE changeset_id=? AND plan_hash=? AND approver=? AND status='APPROVED' AND expires_at>=?",
            (changeset_id, row["plan_hash"], payload.approver, now),
        ).fetchone():
            raise HTTPException(status_code=409, detail="approver has already approved this exact plan")
        approval_id = f"apr_{uuid.uuid4().hex[:16]}"
        expires_at = min(now + payload.ttl_seconds, int(row["expires_at"] or now + payload.ttl_seconds))
        approval_record = {
            "id": approval_id,
            "changeset_id": changeset_id,
            "plan_hash": row["plan_hash"],
            "approver": payload.approver,
            "issued_at": now,
            "expires_at": expires_at,
            "policy_generation": int(row["policy_generation"]),
            "policy_id": "risk-baseline",
            "policy_version": 1,
            "nonce": secrets.token_urlsafe(24),
        }
        approval_record["mac"] = _approval_mac(approval_record)
        conn.execute(
            """INSERT INTO approvals
            (id,changeset_id,plan_hash,approver,status,issued_at,expires_at,decided_at,policy_generation,policy_id,policy_version,nonce,mac)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (approval_id, changeset_id, row["plan_hash"], payload.approver, "APPROVED", now, expires_at, now,
             approval_record["policy_generation"], approval_record["policy_id"], approval_record["policy_version"],
             approval_record["nonce"], approval_record["mac"]),
        )
        required_approvals = 2 if row["risk"] == "CRITICAL" else 1
        approval_count = conn.execute(
            "SELECT COUNT(DISTINCT approver) FROM approvals WHERE changeset_id=? AND plan_hash=? AND status='APPROVED' AND expires_at>=?",
            (changeset_id, row["plan_hash"], now),
        ).fetchone()[0]
        next_state = "APPROVED" if approval_count >= required_approvals else "AWAITING_APPROVAL"
        conn.execute("UPDATE changesets SET state=?,updated_at=? WHERE id=?", (next_state, now, changeset_id))
        db.audit(conn, "changeset.approved", payload.approver, "changeset", changeset_id, {"approval_id": approval_id, "plan_hash": row["plan_hash"], "expires_at": expires_at, "approval_count": approval_count, "required_approvals": required_approvals})
        conn.commit()
    return {"id": approval_id, "changeset_id": changeset_id, "plan_hash": payload.plan_hash, "approver": payload.approver, "status": "APPROVED", "issued_at": now, "expires_at": expires_at, "policy_generation": approval_record["policy_generation"], "policy_id": approval_record["policy_id"], "policy_version": approval_record["policy_version"], "nonce": approval_record["nonce"], "mac": approval_record["mac"], "approval_count": approval_count, "required_approvals": required_approvals, "changeset_state": next_state, "execution_enabled": os.getenv("HERMES_EXECUTION_ENABLED", "false").lower() == "true"}


@app.post("/v1/changesets/{changeset_id}/reject")
def reject_changeset(changeset_id: str, payload: RejectDecision, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    now = int(time.time())
    with closing(db.connect()) as conn:
        row = _changeset(conn, changeset_id)
        if _is_infra_mutation(row["adapter"], row["operation"]):
            _require_approval_bot(authorization)
        else:
            _require_admin(authorization)
        _require_current_policy_generation(conn, row)
        if row["state"] in TERMINAL_CHANGESET_STATES:
            raise HTTPException(status_code=409, detail=f"ChangeSet already terminal: {row['state']}")
        conn.execute("UPDATE changesets SET state='REJECTED',updated_at=? WHERE id=?", (now, changeset_id))
        conn.execute("UPDATE approvals SET status='REJECTED',decided_at=?,reason=? WHERE changeset_id=? AND status='APPROVED'", (now, payload.reason, changeset_id))
        db.audit(conn, "changeset.rejected", payload.actor, "changeset", changeset_id, {"reason": payload.reason, "plan_hash": row["plan_hash"]})
        conn.commit()
        updated = conn.execute("SELECT * FROM changesets WHERE id=?", (changeset_id,)).fetchone()
    return _changeset_dict(updated)


@app.post("/v1/changesets/{changeset_id}/cancel")
def cancel_changeset(changeset_id: str, payload: RejectDecision, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    now = int(time.time())
    with closing(db.connect()) as conn:
        row = _changeset(conn, changeset_id)
        if row["state"] in TERMINAL_CHANGESET_STATES:
            raise HTTPException(status_code=409, detail=f"ChangeSet already terminal: {row['state']}")
        conn.execute("UPDATE changesets SET state='CANCELLED',updated_at=? WHERE id=?", (now, changeset_id))
        conn.execute("UPDATE approvals SET status='CANCELLED',decided_at=?,reason=? WHERE changeset_id=? AND status='APPROVED'", (now, payload.reason, changeset_id))
        db.audit(conn, "changeset.cancelled", payload.actor, "changeset", changeset_id, {"reason": payload.reason, "plan_hash": row["plan_hash"]})
        conn.commit()
        updated = conn.execute("SELECT * FROM changesets WHERE id=?", (changeset_id,)).fetchone()
    return _changeset_dict(updated)


@app.post("/v1/kubernetes/targets/{target_id}/discover")
async def discover_kubernetes_target(target_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        snapshot = _target_snapshot(conn, target_id)
    if snapshot["kind"] != "kubernetes":
        raise HTTPException(status_code=422, detail="target is not kubernetes")
    result = await kubernetes_broker.post("/v1/discover", {"target_snapshot": snapshot})
    with closing(db.connect()) as conn:
        db.audit(conn, "kubernetes.discovered", "admin", "target", target_id, {"snapshot_hash": snapshot["snapshot_hash"]})
        conn.commit()
    return result


@app.post("/v1/changesets/{changeset_id}/preview-live")
async def preview_changeset_live(changeset_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    with closing(db.connect()) as conn:
        row = _changeset(conn, changeset_id)
        _require_infra_actor(row, authorization)
        _require_current_policy_generation(conn, row)
        if row["state"] not in {"PLANNED", "PREVIEWED"}:
            raise HTTPException(status_code=409, detail=f"cannot preview ChangeSet in state {row['state']}")
        if row["adapter"] not in {"kubernetes", "helm"}:
            raise HTTPException(status_code=422, detail="live preview is currently available only for Kubernetes/Helm adapters")
        plan = json.loads(row["plan_json"] or "{}")
        if sha256_hex(plan) != row["plan_hash"]:
            raise HTTPException(status_code=409, detail="stored ChangeSet hash verification failed")
        current = _target_snapshot(conn, row["target_id"])
        if current != plan.get("target_snapshot"):
            raise HTTPException(status_code=409, detail="target or credential metadata changed after planning; create a new ChangeSet")
    try:
        result = await kubernetes_broker.post("/v1/preview", {"plan": plan})
    except HTTPException as exc:
        now = int(time.time())
        state = "POLICY_DENIED" if exc.status_code == 403 else "PREVIEW_FAILED"
        failure = {
            "summary": "Live broker preview denied" if state == "POLICY_DENIED" else "Live broker preview failed",
            "details": {"status_code": exc.status_code, "detail": exc.detail},
            "generated_at": now,
            "source": "kubernetes-broker",
        }
        with closing(db.connect()) as conn:
            conn.execute(
                "UPDATE changesets SET preview_json=?,state=?,updated_at=? WHERE id=?",
                (json.dumps(failure, sort_keys=True), state, now, changeset_id),
            )
            db.audit(
                conn,
                "changeset.policy_denied" if state == "POLICY_DENIED" else "changeset.preview_failed",
                "kubernetes-broker",
                "changeset",
                changeset_id,
                {"plan_hash": row["plan_hash"], "status_code": exc.status_code, "detail": exc.detail},
            )
            conn.commit()
        raise
    now = int(time.time())
    preview = {"summary": result.get("summary", "Live broker preview completed"), "details": result, "generated_at": now, "source": "kubernetes-broker"}
    with closing(db.connect()) as conn:
        conn.execute("UPDATE changesets SET preview_json=?,state='PREVIEWED',updated_at=? WHERE id=?", (json.dumps(preview, sort_keys=True), now, changeset_id))
        db.audit(conn, "changeset.previewed.live", "kubernetes-broker", "changeset", changeset_id, {"plan_hash": row["plan_hash"]})
        conn.commit()
        updated = conn.execute("SELECT * FROM changesets WHERE id=?", (changeset_id,)).fetchone()
    return _changeset_dict(updated)


@app.post("/v1/changesets/{changeset_id}/execute")
async def execute_changeset(changeset_id: str, payload: ExecuteDecision, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    if os.getenv("HERMES_EXECUTION_ENABLED", "false").lower() != "true":
        raise HTTPException(status_code=403, detail="Control Plane execution is disabled; set HERMES_EXECUTION_ENABLED=true only after review")
    now = int(time.time())
    with closing(db.connect()) as conn:
        row = _changeset(conn, changeset_id)
        _require_infra_actor(row, authorization)
        _require_current_policy_generation(conn, row)
        if row["state"] not in {"PREVIEWED", "APPROVED"}:
            raise HTTPException(status_code=409, detail="ChangeSet must have a live preview and any required approval before execution")
        plan = json.loads(row["plan_json"] or "{}")
        if sha256_hex(plan) != row["plan_hash"]:
            raise HTTPException(status_code=409, detail="stored ChangeSet hash verification failed")
        current = _target_snapshot(conn, row["target_id"])
        if current != plan.get("target_snapshot"):
            raise HTTPException(status_code=409, detail="target or credential metadata changed after approval; create a new ChangeSet")
        preview = json.loads(row["preview_json"] or "null")
        if not preview or preview.get("source") != "kubernetes-broker":
            raise HTTPException(status_code=409, detail="a live Kubernetes Broker preview is required")
        approval_ids_to_consume: list[str] = []
        if row["approval_required"]:
            required_approvals = 2 if row["risk"] == "CRITICAL" else 1
            approval_rows = conn.execute(
                "SELECT * FROM approvals WHERE changeset_id=? AND plan_hash=? AND status='APPROVED' AND consumed_at IS NULL ORDER BY issued_at ASC, id ASC",
                (changeset_id, row["plan_hash"]),
            ).fetchall()
            valid_by_approver: dict[str, Any] = {}
            for approval in approval_rows:
                if approval["approver"] not in valid_by_approver and _approval_is_valid(approval, changeset=row, now=now):
                    valid_by_approver[approval["approver"]] = approval
            if len(valid_by_approver) < required_approvals:
                raise HTTPException(status_code=409, detail=f"{required_approvals} valid distinct integrity-checked approval(s) required for this exact plan hash")
            approval_ids_to_consume = [str(approval["id"]) for approval in list(valid_by_approver.values())[:required_approvals]]
        preview_details = (preview.get("details") or {}) if isinstance(preview, dict) else {}
        preconditions = {}
        if preview_details.get("live_state_hash"):
            preconditions["live_state_hash"] = preview_details["live_state_hash"]
        if preview_details.get("release_snapshot_hash"):
            preconditions["release_snapshot_hash"] = preview_details["release_snapshot_hash"]
        if preview_details.get("toolchain_binding_hash"):
            preconditions["toolchain_binding_hash"] = preview_details["toolchain_binding_hash"]
        try:
            ticket, signature = issue_ticket(
                changeset_id,
                row["plan_hash"],
                plan,
                preconditions=preconditions,
            )
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        if approval_ids_to_consume:
            placeholders = ",".join("?" for _ in approval_ids_to_consume)
            conn.execute(
                f"UPDATE approvals SET status='CONSUMED',consumed_at=?,decided_at=? WHERE id IN ({placeholders}) AND status='APPROVED' AND consumed_at IS NULL",
                (now, now, *approval_ids_to_consume),
            )
        conn.execute("UPDATE changesets SET state='EXECUTING',updated_at=? WHERE id=?", (now, changeset_id))
        db.audit(conn, "changeset.execution.started", payload.actor, "changeset", changeset_id, {"plan_hash": row["plan_hash"], "consumed_approval_ids": approval_ids_to_consume})
        conn.commit()
    try:
        result = await kubernetes_broker.post("/v1/execute", {"ticket": ticket, "signature": signature})
        state = "EXECUTED"
    except HTTPException as exc:
        result = {"error": exc.detail, "status_code": exc.status_code}
        state = "FAILED"
    finished = int(time.time())
    with closing(db.connect()) as conn:
        conn.execute("UPDATE changesets SET state=?,execution_json=?,executed_at=?,updated_at=? WHERE id=?", (state, json.dumps(result, sort_keys=True), finished, finished, changeset_id))
        db.audit(conn, f"changeset.execution.{state.lower()}", payload.actor, "changeset", changeset_id, {"plan_hash": ticket["plan_hash"]})
        conn.commit()
        updated = conn.execute("SELECT * FROM changesets WHERE id=?", (changeset_id,)).fetchone()
    if state == "FAILED":
        raise HTTPException(status_code=502, detail=_changeset_dict(updated))
    return _changeset_dict(updated)


@app.get("/v1/kubernetes/broker-health")
async def kubernetes_broker_health() -> dict[str, Any]:
    return await kubernetes_broker.health()


@app.get("/v1/changesets/{changeset_id}/approvals")
def list_approvals(changeset_id: str, authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        if not conn.execute("SELECT 1 FROM changesets WHERE id=?", (changeset_id,)).fetchone():
            raise HTTPException(status_code=404, detail="changeset not found")
        rows = conn.execute("SELECT * FROM approvals WHERE changeset_id=? ORDER BY issued_at DESC", (changeset_id,)).fetchall()
    return [dict(row) for row in rows]


@app.get("/v1/audit")
def list_audit(limit: int = Query(default=200, ge=1, le=2000), subject_id: str | None = None) -> list[dict[str, Any]]:
    with closing(db.connect()) as conn:
        if subject_id:
            rows = conn.execute("SELECT * FROM audit_events WHERE subject_id=? ORDER BY id DESC LIMIT ?", (subject_id, limit)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        item["payload"] = json.loads(item.pop("payload_json") or "{}")
        out.append(item)
    return out


@app.get("/v1/audit/export", response_class=PlainTextResponse)
def export_audit(authorization: str | None = Header(default=None)) -> PlainTextResponse:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
    lines = []
    for row in rows:
        item = dict(row)
        item["payload"] = json.loads(item.pop("payload_json") or "{}")
        lines.append(json.dumps(item, sort_keys=True, separators=(",", ":")))
    body = "\n".join(lines) + ("\n" if lines else "")
    return PlainTextResponse(body, media_type="application/x-ndjson", headers={"X-Hermes-Audit-SHA256": sha256_hex(body)})


@app.post("/v1/audit/retention")
def enforce_audit_retention(days: int = Query(ge=1, le=3650), actor: str = Query(min_length=1, max_length=160), authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    cutoff = int(time.time()) - days * 86400
    with closing(db.connect()) as conn:
        cur = conn.execute("DELETE FROM audit_events WHERE created_at < ?", (cutoff,))
        deleted = cur.rowcount
        db.audit(conn, "audit.retention_enforced", actor, "audit", "global", {"days": days, "cutoff": cutoff, "deleted": deleted})
        conn.commit()
    return {"retention_days": days, "deleted": deleted, "cutoff": cutoff}


# --- 0.5.11-dev.3 Cluster Factory + core infrastructure/day-2 contracts ---

@app.get("/v1/cluster-factory/contracts")
def cluster_factory_contracts() -> dict[str, Any]:
    return {
        "resource_types": ["ClusterBlueprint", "ClusterProfile", "Cluster", "NodeRole", "ProvisioningRun", "AddonPlan", "UpgradePlan", "BackupPlan"],
        "providers": cluster_factory.CLUSTER_PROVIDERS,
        "addons": cluster_factory.ADDON_CATALOG,
        "operational_profiles": cluster_factory.OPERATIONAL_PROFILES,
        "radar": cluster_factory.RADAR_CONTRACT,
        "hubble": cluster_factory.HUBBLE_CONTRACT,
        "diagnostics": cluster_factory.NATIVE_DIAGNOSTICS,
        "mutation_invariant": "intent -> typed plan -> ChangeSet -> deterministic preview/diff -> risk -> policy -> approval -> exact-hash binding -> constrained execution -> verification -> audit",
        "aban_runtime_dependency": False,
    }


@app.get("/v1/cluster-blueprints")
def list_cluster_blueprints(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM cluster_blueprints ORDER BY name").fetchall()
    return [_blueprint_dict(row) for row in rows]


def _validate_blueprint_addon_pins(*, addon_defaults: list[str], addon_versions: dict[str, str], hubble_enabled: bool, radar_enabled: bool) -> None:
    required = ["cilium", "hermes-agent"]
    if hubble_enabled:
        required.append("hubble")
    if radar_enabled:
        required.append("radar")
    selected = list(dict.fromkeys([*required, *addon_defaults]))
    try:
        cluster_factory._require_supported_addons(selected, addon_versions)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _validate_blueprint_artifact_dependency_ids(conn, artifact_ids: list[str]) -> None:
    if len(artifact_ids) != len(set(artifact_ids)):
        raise HTTPException(status_code=422, detail="cluster blueprint artifact dependency IDs must be unique")
    for artifact_id in artifact_ids:
        if not re.fullmatch(r"art_[0-9a-f]{16}", artifact_id):
            raise HTTPException(status_code=422, detail="cluster blueprint artifact dependency ID is invalid")
        _get_artifact_mirror_item(conn, artifact_id)


def _blueprint_artifact_manifest(conn, blueprint_id: str) -> dict[str, Any]:
    blueprint = _blueprint_dict(_get_blueprint(conn, blueprint_id))
    artifacts = [_artifact_mirror_item_dict(row) for row in conn.execute("SELECT * FROM artifact_mirror_items ORDER BY id").fetchall()]
    return cluster_factory.resolve_blueprint_artifact_manifest(blueprint=blueprint, artifacts=artifacts)


@app.get("/v1/cluster-factory/operational-profiles")
def list_operational_profiles() -> dict[str, Any]:
    return cluster_factory.OPERATIONAL_PROFILES


@app.post("/v1/cluster-blueprints", status_code=201)
def create_cluster_blueprint(payload: ClusterBlueprintCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    _validate_blueprint_addon_pins(addon_defaults=payload.addon_defaults, addon_versions=payload.addon_versions, hubble_enabled=payload.hubble_enabled, radar_enabled=payload.radar_enabled)
    blueprint_id = f"cbp_{uuid.uuid4().hex[:16]}"
    now = int(time.time())
    with closing(db.connect()) as conn:
        _validate_blueprint_artifact_dependency_ids(conn, payload.artifact_dependencies)
        try:
            conn.execute(
                "INSERT INTO cluster_blueprints (id,name,description,provider,provider_version,kubernetes_version,network_plugin,hubble_enabled,radar_enabled,topology_json,addon_defaults_json,addon_versions_json,artifact_dependencies_json,labels_json,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (blueprint_id, payload.name, payload.description, payload.provider, payload.provider_version, payload.kubernetes_version, payload.network_plugin, int(payload.hubble_enabled), int(payload.radar_enabled), json.dumps(payload.topology, sort_keys=True), json.dumps(payload.addon_defaults), json.dumps(payload.addon_versions, sort_keys=True), json.dumps(payload.artifact_dependencies), json.dumps(payload.labels, sort_keys=True), "configured", now, now),
            )
        except Exception as exc:
            if "UNIQUE constraint failed" in str(exc):
                raise HTTPException(status_code=409, detail="cluster blueprint name already exists") from exc
            raise
        db.audit(conn, "cluster_blueprint.created", "admin", "cluster_blueprint", blueprint_id, {"provider": payload.provider, "provider_version": payload.provider_version, "kubernetes_version": payload.kubernetes_version})
        conn.commit()
        row = _get_blueprint(conn, blueprint_id)
    return _blueprint_dict(row)


@app.post("/v1/cluster-blueprints/from-operational-profile", status_code=201)
def create_blueprint_from_operational_profile(payload: OperationalProfileBlueprintCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    preset = cluster_factory.OPERATIONAL_PROFILES[payload.operational_profile]
    addons = list(preset["addons"])
    _validate_blueprint_addon_pins(addon_defaults=addons, addon_versions=payload.addon_versions, hubble_enabled=True, radar_enabled=True)
    labels = {**payload.labels, "operational_profile": payload.operational_profile}
    blueprint_id = f"cbp_{uuid.uuid4().hex[:16]}"
    now = int(time.time())
    with closing(db.connect()) as conn:
        _validate_blueprint_artifact_dependency_ids(conn, payload.artifact_dependencies)
        try:
            conn.execute(
                "INSERT INTO cluster_blueprints (id,name,description,provider,provider_version,kubernetes_version,network_plugin,hubble_enabled,radar_enabled,topology_json,addon_defaults_json,addon_versions_json,artifact_dependencies_json,labels_json,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (blueprint_id, payload.name, payload.description, preset["provider"], payload.provider_version, payload.kubernetes_version, "cilium", 1, 1, json.dumps(preset["topology"], sort_keys=True), json.dumps(addons), json.dumps(payload.addon_versions, sort_keys=True), json.dumps(payload.artifact_dependencies), json.dumps(labels, sort_keys=True), "configured", now, now),
            )
        except Exception as exc:
            if "UNIQUE constraint failed" in str(exc):
                raise HTTPException(status_code=409, detail="cluster blueprint name already exists") from exc
            raise
        db.audit(conn, "cluster_blueprint.created_from_operational_profile", "admin", "cluster_blueprint", blueprint_id, {"operational_profile": payload.operational_profile, "provider": preset["provider"], "provider_version": payload.provider_version, "kubernetes_version": payload.kubernetes_version})
        conn.commit()
        row = _get_blueprint(conn, blueprint_id)
    return _blueprint_dict(row)


@app.get("/v1/cluster-blueprints/{blueprint_id}")
def get_cluster_blueprint(blueprint_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        row = _get_blueprint(conn, blueprint_id)
    return _blueprint_dict(row)


@app.put("/v1/cluster-blueprints/{blueprint_id}/artifact-dependencies")
def set_cluster_blueprint_artifact_dependencies(blueprint_id: str, payload: ClusterBlueprintArtifactDependenciesUpdate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        _get_blueprint(conn, blueprint_id)
        _validate_blueprint_artifact_dependency_ids(conn, payload.artifact_dependencies)
        now = int(time.time())
        conn.execute("UPDATE cluster_blueprints SET artifact_dependencies_json=?,updated_at=? WHERE id=?", (json.dumps(payload.artifact_dependencies), now, blueprint_id))
        db.audit(conn, "cluster_blueprint.artifact_dependencies_updated", "admin", "cluster_blueprint", blueprint_id, {"artifact_ids": payload.artifact_dependencies})
        conn.commit()
        row = _get_blueprint(conn, blueprint_id)
    return _blueprint_dict(row)


@app.get("/v1/cluster-blueprints/{blueprint_id}/artifact-manifest")
def get_cluster_blueprint_artifact_manifest(blueprint_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        manifest = _blueprint_artifact_manifest(conn, blueprint_id)
        db.audit(conn, "cluster_blueprint.artifact_manifest_resolved", "admin", "cluster_blueprint", blueprint_id, {"manifest_hash": manifest["manifest_hash"], "state": manifest["state"], "issue_count": len(manifest["issues"])})
        conn.commit()
    return manifest


@app.get("/v1/cluster-profiles")
def list_cluster_profiles(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM cluster_profiles ORDER BY name").fetchall()
    return [_profile_dict(row) for row in rows]


@app.post("/v1/cluster-profiles", status_code=201)
def create_cluster_profile(payload: ClusterProfileCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    if len(payload.server_ids) != len(set(payload.server_ids)):
        raise HTTPException(status_code=422, detail="cluster profile server_ids must be unique")
    profile_id = f"cpf_{uuid.uuid4().hex[:16]}"
    now = int(time.time())
    with closing(db.connect()) as conn:
        _get_environment(conn, payload.environment_id)
        blueprint = _get_blueprint(conn, payload.blueprint_id)
        if blueprint["status"] != "configured":
            raise HTTPException(status_code=409, detail="cluster blueprint is disabled")
        for server_id in payload.server_ids:
            server = _get_server(conn, server_id)
            if server["environment_id"] != payload.environment_id:
                raise HTTPException(status_code=409, detail=f"server {server_id} is in a different environment")
            if server["status"] != "configured":
                raise HTTPException(status_code=409, detail=f"server {server_id} is disabled")
        try:
            conn.execute(
                "INSERT INTO cluster_profiles (id,name,environment_id,blueprint_id,server_ids_json,overrides_json,labels_json,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (profile_id, payload.name, payload.environment_id, payload.blueprint_id, json.dumps(payload.server_ids), json.dumps(payload.overrides, sort_keys=True), json.dumps(payload.labels, sort_keys=True), "configured", now, now),
            )
        except Exception as exc:
            if "UNIQUE constraint failed" in str(exc):
                raise HTTPException(status_code=409, detail="cluster profile name already exists") from exc
            raise
        db.audit(conn, "cluster_profile.created", "admin", "cluster_profile", profile_id, {"blueprint_id": payload.blueprint_id, "server_count": len(payload.server_ids)})
        conn.commit()
        row = _get_profile(conn, profile_id)
    return _profile_dict(row)


@app.get("/v1/cluster-profiles/{profile_id}")
def get_cluster_profile(profile_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        row = _get_profile(conn, profile_id)
    return _profile_dict(row)


@app.get("/v1/node-roles")
def list_node_roles(profile_id: str | None = None, authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM node_roles WHERE (? IS NULL OR profile_id=?) ORDER BY created_at,id", (profile_id, profile_id)).fetchall()
    return [_node_role_dict(row) for row in rows]


@app.post("/v1/node-roles", status_code=201)
def create_node_role(payload: NodeRoleCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    if len(payload.server_ids) != len(set(payload.server_ids)):
        raise HTTPException(status_code=422, detail="NodeRole server_ids must be unique")
    role_id = f"nrl_{uuid.uuid4().hex[:16]}"
    now = int(time.time())
    with closing(db.connect()) as conn:
        profile = _profile_dict(_get_profile(conn, payload.profile_id))
        outside = sorted(set(payload.server_ids) - set(profile["server_ids"]))
        if outside:
            raise HTTPException(status_code=409, detail=f"NodeRole servers are not in profile: {', '.join(outside)}")
        assigned: set[str] = set()
        for row in conn.execute("SELECT server_ids_json FROM node_roles WHERE profile_id=? AND status='configured'", (payload.profile_id,)).fetchall():
            assigned.update(json.loads(row["server_ids_json"] or "[]"))
        overlap = sorted(assigned.intersection(payload.server_ids))
        if overlap:
            raise HTTPException(status_code=409, detail=f"servers already have a NodeRole: {', '.join(overlap)}")
        conn.execute(
            "INSERT INTO node_roles (id,profile_id,role,server_ids_json,configuration_json,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
            (role_id, payload.profile_id, payload.role, json.dumps(payload.server_ids), json.dumps(payload.configuration, sort_keys=True), "configured", now, now),
        )
        db.audit(conn, "node_role.created", "admin", "node_role", role_id, {"profile_id": payload.profile_id, "role": payload.role, "server_ids": payload.server_ids})
        conn.commit()
        row = conn.execute("SELECT * FROM node_roles WHERE id=?", (role_id,)).fetchone()
    return _node_role_dict(row)


@app.get("/v1/clusters")
def list_clusters(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM clusters ORDER BY name").fetchall()
    return [_cluster_dict(row) for row in rows]


@app.post("/v1/clusters", status_code=201)
def create_cluster(payload: ClusterCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    cluster_id = f"clu_{uuid.uuid4().hex[:16]}"
    now = int(time.time())
    with closing(db.connect()) as conn:
        _get_environment(conn, payload.environment_id)
        profile = _profile_dict(_get_profile(conn, payload.profile_id))
        if profile["environment_id"] != payload.environment_id:
            raise HTTPException(status_code=409, detail="cluster and profile environments must match")
        blueprint = _blueprint_dict(_get_blueprint(conn, profile["blueprint_id"]))
        try:
            conn.execute(
                "INSERT INTO clusters (id,name,environment_id,profile_id,provider,kubernetes_version,network_plugin,state,labels_json,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (cluster_id, payload.name, payload.environment_id, payload.profile_id, blueprint["provider"], blueprint["kubernetes_version"], blueprint["network_plugin"], "DRAFT", json.dumps(payload.labels, sort_keys=True), "configured", now, now),
            )
        except Exception as exc:
            if "UNIQUE constraint failed" in str(exc):
                raise HTTPException(status_code=409, detail="cluster name already exists") from exc
            raise
        db.audit(conn, "cluster.created", "admin", "cluster", cluster_id, {"profile_id": payload.profile_id, "provider": blueprint["provider"]})
        conn.commit()
        row = _get_cluster(conn, cluster_id)
    return _cluster_dict(row)


@app.get("/v1/clusters/{cluster_id}")
def get_cluster(cluster_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        row = _get_cluster(conn, cluster_id)
    return _cluster_dict(row)


@app.get("/v1/provisioning-runs")
def list_provisioning_runs(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM provisioning_runs ORDER BY created_at DESC,id DESC").fetchall()
    return [_provisioning_run_dict(row) for row in rows]


@app.post("/v1/clusters/{cluster_id}/provisioning-runs", status_code=201)
def create_provisioning_run(cluster_id: str, payload: ProvisioningRunCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_bot(authorization)
    _require_bot_origin(payload.source_channel)
    with closing(db.connect()) as conn:
        cluster = _cluster_dict(_get_cluster(conn, cluster_id))
        if cluster["state"] not in {"DRAFT", "ERROR"}:
            raise HTTPException(status_code=409, detail=f"cluster cannot be provisioned from state {cluster['state']}")
        profile = _profile_dict(_get_profile(conn, cluster["profile_id"]))
        blueprint = _blueprint_dict(_get_blueprint(conn, profile["blueprint_id"]))
        roles = [_node_role_dict(row) for row in conn.execute("SELECT * FROM node_roles WHERE profile_id=? AND status='configured' ORDER BY created_at,id", (profile["id"],)).fetchall()]
        servers = [_server_dict(_get_server(conn, server_id)) for server_id in profile["server_ids"]]
        artifact_manifest = None
        if blueprint.get("artifact_dependencies"):
            artifact_manifest = _blueprint_artifact_manifest(conn, blueprint["id"])
        try:
            typed_plan = cluster_factory.provisioning_plan(
                cluster=cluster,
                blueprint=blueprint,
                profile=profile,
                node_roles=roles,
                servers=servers,
                artifact_manifest=artifact_manifest,
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        params = {"resource_type": "ProvisioningRun", "typed_plan": typed_plan, "profile_id": profile["id"], "provider": blueprint["provider"]}
        if artifact_manifest is not None:
            params["artifact_manifest_hash"] = artifact_manifest["manifest_hash"]
        changeset = _insert_changeset(
            conn, operation="cluster.provision.apply", adapter="bootstrap", target_id=cluster_id,
            requested_by=payload.requested_by, source_channel=payload.source_channel, source_revision=None,
            parameters=params, policy_generation=db.get_policy_generation(conn), ttl_seconds=payload.ttl_seconds,
        )
        preview = {"summary": f"Provision cluster {cluster['name']} with {blueprint['provider']}", "details": typed_plan, "source": "cluster-factory-deterministic-planner"}
        conn.execute("UPDATE changesets SET preview_json=?,state='PREVIEWED',updated_at=? WHERE id=?", (json.dumps(preview, sort_keys=True), int(time.time()), changeset["id"]))
        now = int(time.time())
        coordinator = next((node for node in typed_plan["nodes"] if node["role"] in {"control-plane", "control-plane-worker"}), typed_plan["nodes"][0])
        job_id = f"job_{uuid.uuid4().hex[:16]}"
        job_ids: list[str] = [job_id]
        request = {
            "cluster_id": cluster_id,
            "provider": blueprint["provider"],
            "coordinator_server_id": coordinator["server_id"],
            "typed_plan_hash": typed_plan["plan_hash"],
            "executor": "cluster-provider-worker",
        }
        if artifact_manifest is not None:
            request["artifact_manifest_hash"] = artifact_manifest["manifest_hash"]
            request["offline_artifact_count"] = len(typed_plan["artifact_supply"]["dependency_order"])
        conn.execute(
            "INSERT INTO provider_jobs (id,provider_id,server_id,changeset_id,operation,state,stage,attempt,max_attempts,plan_hash,request_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (job_id, blueprint["provider"], coordinator["server_id"], changeset["id"], "cluster.provision.apply", "WAITING_APPROVAL", "plan", 1, 3, changeset["plan_hash"], json.dumps(request, sort_keys=True), now, now),
        )
        _provider_job_event(conn, job_id, "plan", "WAITING_APPROVAL", "Cluster provisioning coordinator job is blocked on exact ChangeSet approval", {"cluster_id": cluster_id, "coordinator_server_id": coordinator["server_id"], "node_count": len(typed_plan["nodes"])})
        run_id = f"prn_{uuid.uuid4().hex[:16]}"
        conn.execute(
            "INSERT INTO provisioning_runs (id,cluster_id,profile_id,provider,state,stage,changeset_id,provider_job_ids_json,plan_json,result_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, cluster_id, profile["id"], blueprint["provider"], "WAITING_APPROVAL", "plan", changeset["id"], json.dumps(job_ids), json.dumps(typed_plan, sort_keys=True), None, now, now),
        )
        conn.execute("UPDATE clusters SET state='PLANNED',updated_at=? WHERE id=?", (now, cluster_id))
        audit_payload = {"cluster_id": cluster_id, "changeset_id": changeset["id"], "provider_job_ids": job_ids, "typed_plan_hash": typed_plan["plan_hash"]}
        if artifact_manifest is not None:
            audit_payload["artifact_manifest_hash"] = artifact_manifest["manifest_hash"]
            audit_payload["offline_artifact_count"] = len(typed_plan["artifact_supply"]["dependency_order"])
        db.audit(conn, "cluster.provisioning_planned", payload.requested_by, "provisioning_run", run_id, audit_payload)
        conn.commit()
        row = conn.execute("SELECT * FROM provisioning_runs WHERE id=?", (run_id,)).fetchone()
        chg = conn.execute("SELECT * FROM changesets WHERE id=?", (changeset["id"],)).fetchone()
    return {**_provisioning_run_dict(row), "changeset": _changeset_dict(chg)}


@app.post("/v1/provisioning-runs/{run_id}/refresh")
def refresh_provisioning_run(run_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    now = int(time.time())
    with closing(db.connect()) as conn:
        row = conn.execute("SELECT * FROM provisioning_runs WHERE id=?", (run_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="provisioning run not found")
        run = _provisioning_run_dict(row)
        jobs = [conn.execute("SELECT * FROM provider_jobs WHERE id=?", (job_id,)).fetchone() for job_id in run["provider_job_ids"]]
        if any(job is None for job in jobs):
            raise HTTPException(status_code=409, detail="provisioning run references a missing provider job")
        states = [job["state"] for job in jobs]
        if all(state == "SUCCEEDED" for state in states):
            state, stage, cluster_state = "SUCCEEDED", "verify", "READY"
        elif any(state == "FAILED" for state in states):
            state, stage, cluster_state = "FAILED", "verify", "ERROR"
        elif any(state == "RUNNING" for state in states):
            state, stage, cluster_state = "RUNNING", "apply", "PROVISIONING"
        elif all(state == "READY" for state in states):
            state, stage, cluster_state = "READY", "apply", "PLANNED"
        else:
            state, stage, cluster_state = "WAITING_APPROVAL", "plan", "PLANNED"
        result = {"provider_job_states": {job["id"]: job["state"] for job in jobs}}
        conn.execute("UPDATE provisioning_runs SET state=?,stage=?,result_json=?,updated_at=? WHERE id=?", (state, stage, json.dumps(result, sort_keys=True), now, run_id))
        conn.execute("UPDATE clusters SET state=?,updated_at=? WHERE id=?", (cluster_state, now, run["cluster_id"]))
        db.audit(conn, "provisioning_run.refreshed", "admin", "provisioning_run", run_id, {"state": state, "cluster_state": cluster_state})
        conn.commit()
        updated = conn.execute("SELECT * FROM provisioning_runs WHERE id=?", (run_id,)).fetchone()
    return _provisioning_run_dict(updated)


@app.get("/v1/addon-plans")
def list_addon_plans(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM addon_plans ORDER BY created_at DESC,id DESC").fetchall()
    return [_plan_resource_dict(row) for row in rows]


@app.post("/v1/clusters/{cluster_id}/addon-plans", status_code=201)
def create_addon_plan(cluster_id: str, payload: AddonPlanCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_bot(authorization)
    _require_bot_origin(payload.source_channel)
    with closing(db.connect()) as conn:
        cluster = _cluster_dict(_get_cluster(conn, cluster_id))
        if cluster["state"] != "READY":
            raise HTTPException(status_code=409, detail="cluster must be READY before add-on planning")
        try:
            typed_plan = cluster_factory.addon_plan(cluster=cluster, addons=payload.addons, versions=payload.versions, configuration=payload.configuration)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        changeset = _insert_changeset(conn, operation="cluster.addons.apply", adapter="provider", target_id=cluster_id, requested_by=payload.requested_by, source_channel=payload.source_channel, source_revision=None, parameters={"resource_type": "AddonPlan", "typed_plan": typed_plan}, policy_generation=db.get_policy_generation(conn), ttl_seconds=payload.ttl_seconds)
        preview = {"summary": f"Apply {len(payload.addons)} governed add-ons to {cluster['name']}", "details": typed_plan, "source": "cluster-factory-addon-planner"}
        conn.execute("UPDATE changesets SET preview_json=?,state='PREVIEWED',updated_at=? WHERE id=?", (json.dumps(preview, sort_keys=True), int(time.time()), changeset["id"]))
        plan_id, now = f"adp_{uuid.uuid4().hex[:16]}", int(time.time())
        conn.execute("INSERT INTO addon_plans (id,cluster_id,state,changeset_id,plan_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?)", (plan_id, cluster_id, "PLANNED", changeset["id"], json.dumps(typed_plan, sort_keys=True), now, now))
        db.audit(conn, "addon_plan.created", payload.requested_by, "addon_plan", plan_id, {"cluster_id": cluster_id, "changeset_id": changeset["id"], "plan_hash": typed_plan["plan_hash"]})
        conn.commit()
        row = conn.execute("SELECT * FROM addon_plans WHERE id=?", (plan_id,)).fetchone()
        chg = conn.execute("SELECT * FROM changesets WHERE id=?", (changeset["id"],)).fetchone()
    return {**_plan_resource_dict(row), "changeset": _changeset_dict(chg)}


@app.get("/v1/upgrade-plans")
def list_upgrade_plans(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM upgrade_plans ORDER BY created_at DESC,id DESC").fetchall()
    return [_plan_resource_dict(row) for row in rows]


@app.post("/v1/clusters/{cluster_id}/upgrade-plans", status_code=201)
def create_upgrade_plan(cluster_id: str, payload: UpgradePlanCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_bot(authorization)
    _require_bot_origin(payload.source_channel)
    with closing(db.connect()) as conn:
        cluster = _cluster_dict(_get_cluster(conn, cluster_id))
        if cluster["state"] != "READY":
            raise HTTPException(status_code=409, detail="cluster must be READY before upgrade planning")
        if payload.target_version == cluster["kubernetes_version"]:
            raise HTTPException(status_code=422, detail="target_version must differ from the current Kubernetes version")
        typed_plan = cluster_factory.upgrade_plan(cluster=cluster, provider=cluster["provider"], target_version=payload.target_version, strategy=payload.strategy)
        changeset = _insert_changeset(conn, operation="cluster.upgrade", adapter="bootstrap", target_id=cluster_id, requested_by=payload.requested_by, source_channel=payload.source_channel, source_revision=None, parameters={"resource_type": "UpgradePlan", "typed_plan": typed_plan}, policy_generation=db.get_policy_generation(conn), ttl_seconds=payload.ttl_seconds)
        preview = {"summary": f"Upgrade {cluster['name']} from {cluster['kubernetes_version']} to {payload.target_version}", "details": typed_plan, "source": "cluster-factory-upgrade-planner"}
        conn.execute("UPDATE changesets SET preview_json=?,state='PREVIEWED',updated_at=? WHERE id=?", (json.dumps(preview, sort_keys=True), int(time.time()), changeset["id"]))
        plan_id, now = f"upg_{uuid.uuid4().hex[:16]}", int(time.time())
        conn.execute("INSERT INTO upgrade_plans (id,cluster_id,state,changeset_id,plan_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?)", (plan_id, cluster_id, "PLANNED", changeset["id"], json.dumps(typed_plan, sort_keys=True), now, now))
        db.audit(conn, "upgrade_plan.created", payload.requested_by, "upgrade_plan", plan_id, {"cluster_id": cluster_id, "changeset_id": changeset["id"], "plan_hash": typed_plan["plan_hash"]})
        conn.commit()
        row = conn.execute("SELECT * FROM upgrade_plans WHERE id=?", (plan_id,)).fetchone()
        chg = conn.execute("SELECT * FROM changesets WHERE id=?", (changeset["id"],)).fetchone()
    return {**_plan_resource_dict(row), "changeset": _changeset_dict(chg)}


@app.get("/v1/backup-plans")
def list_backup_plans(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM backup_plans ORDER BY created_at DESC,id DESC").fetchall()
    return [_plan_resource_dict(row) for row in rows]


@app.post("/v1/clusters/{cluster_id}/backup-plans", status_code=201)
def create_backup_plan(cluster_id: str, payload: BackupPlanCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_bot(authorization)
    _require_bot_origin(payload.source_channel)
    with closing(db.connect()) as conn:
        cluster = _cluster_dict(_get_cluster(conn, cluster_id))
        if cluster["state"] != "READY":
            raise HTTPException(status_code=409, detail="cluster must be READY before backup planning")
        typed_plan = cluster_factory.backup_plan(cluster=cluster, provider=payload.provider, schedule=payload.schedule, retention_count=payload.retention_count, scope=payload.scope)
        changeset = _insert_changeset(conn, operation="cluster.backup.apply", adapter="provider", target_id=cluster_id, requested_by=payload.requested_by, source_channel=payload.source_channel, source_revision=None, parameters={"resource_type": "BackupPlan", "typed_plan": typed_plan}, policy_generation=db.get_policy_generation(conn), ttl_seconds=payload.ttl_seconds)
        preview = {"summary": f"Configure governed backup plan for {cluster['name']}", "details": typed_plan, "source": "cluster-factory-backup-planner"}
        conn.execute("UPDATE changesets SET preview_json=?,state='PREVIEWED',updated_at=? WHERE id=?", (json.dumps(preview, sort_keys=True), int(time.time()), changeset["id"]))
        plan_id, now = f"bkp_{uuid.uuid4().hex[:16]}", int(time.time())
        conn.execute("INSERT INTO backup_plans (id,cluster_id,state,changeset_id,plan_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?)", (plan_id, cluster_id, "PLANNED", changeset["id"], json.dumps(typed_plan, sort_keys=True), now, now))
        db.audit(conn, "backup_plan.created", payload.requested_by, "backup_plan", plan_id, {"cluster_id": cluster_id, "changeset_id": changeset["id"], "plan_hash": typed_plan["plan_hash"]})
        conn.commit()
        row = conn.execute("SELECT * FROM backup_plans WHERE id=?", (plan_id,)).fetchone()
        chg = conn.execute("SELECT * FROM changesets WHERE id=?", (changeset["id"],)).fetchone()
    return {**_plan_resource_dict(row), "changeset": _changeset_dict(chg)}


def _configured_radar_integration(conn, cluster: dict[str, Any], integration_id: str | None) -> dict[str, Any]:
    if integration_id:
        row = conn.execute("SELECT * FROM integrations WHERE id=?", (integration_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Radar integration not found")
    else:
        row = conn.execute(
            "SELECT * FROM integrations WHERE kind='radar' AND environment_id=? AND status='configured' ORDER BY name,id LIMIT 1",
            (cluster["environment_id"],),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=503, detail="no configured Radar integration exists for the cluster environment")
    integration = _integration_dict(row)
    if integration["kind"] != "radar":
        raise HTTPException(status_code=422, detail="integration_id must reference a Radar integration")
    if integration["environment_id"] != cluster["environment_id"]:
        raise HTTPException(status_code=403, detail="Radar integration belongs to a different environment")
    if integration["status"] != "configured":
        raise HTTPException(status_code=409, detail="Radar integration is disabled")
    if integration["connection_mode"] != "direct":
        raise HTTPException(status_code=501, detail="agent-routed Radar integration is not implemented yet")
    if not integration.get("endpoint"):
        raise HTTPException(status_code=422, detail="Radar integration has no MCP endpoint")
    if integration.get("credential_ref"):
        raise HTTPException(status_code=501, detail="authenticated Radar credential delivery must use a provider worker; direct Control Plane secret resolution is forbidden")
    _reject_embedded_url_credentials(integration["endpoint"], "Radar endpoint")
    return integration


def _native_kubernetes_target(conn, cluster: dict[str, Any], target_id: str | None) -> dict[str, Any]:
    if not target_id:
        raise HTTPException(status_code=503, detail="native_target_id is required for native Kubernetes fallback")
    row = conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="native Kubernetes target not found")
    target = _target_dict(row)
    if target["kind"] != "kubernetes":
        raise HTTPException(status_code=422, detail="native_target_id must reference a Kubernetes target")
    if target["environment_id"] != cluster["environment_id"]:
        raise HTTPException(status_code=403, detail="native Kubernetes target belongs to a different environment")
    if target["status"] != "configured":
        raise HTTPException(status_code=409, detail="native Kubernetes target is disabled")
    return _target_snapshot(conn, target["id"])


def _native_inventory(discovery: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for bucket in ("namespaces", "nodes", "workloads"):
        value = discovery.get(bucket)
        if isinstance(value, dict):
            for item in value.get("items") or []:
                if isinstance(item, dict):
                    items.append(item)
    return items


def _native_resource_identity(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    return {
        "kind": item.get("kind"),
        "apiVersion": item.get("apiVersion"),
        "name": metadata.get("name"),
        "namespace": metadata.get("namespace"),
        "labels": metadata.get("labels") or {},
        "spec": item.get("spec") or {},
        "status": item.get("status") or {},
    }


def _native_intelligence_result(tool: str, arguments: dict[str, Any], discovery: dict[str, Any]) -> dict[str, Any]:
    discovery = radar_provider.redact(discovery)
    inventory = [_native_resource_identity(item) for item in _native_inventory(discovery)]
    namespace = str(arguments.get("namespace") or "").strip()
    if namespace:
        inventory = [item for item in inventory if not item.get("namespace") or item.get("namespace") == namespace or (str(item.get("kind")).lower() == "namespace" and item.get("name") == namespace)]

    if tool == "get_dashboard":
        by_kind: dict[str, int] = {}
        issues = []
        for item in inventory:
            kind = str(item.get("kind") or "Unknown")
            by_kind[kind] = by_kind.get(kind, 0) + 1
            status = item.get("status") or {}
            desired = status.get("replicas")
            ready = status.get("readyReplicas", status.get("numberReady"))
            if isinstance(desired, int) and isinstance(ready, int) and ready < desired:
                issues.append({"kind": kind, "namespace": item.get("namespace"), "name": item.get("name"), "ready": ready, "desired": desired})
        return {"coverage": "native-inventory", "resource_counts": by_kind, "issues": issues[:200]}

    if tool == "list_resources":
        kind = str(arguments.get("kind") or "").lower()
        if not kind:
            raise HTTPException(status_code=422, detail="native list_resources requires kind")
        matches = [item for item in inventory if str(item.get("kind") or "").lower() == kind]
        return {"coverage": "native-discovery", "items": matches[:200], "count": len(matches)}

    if tool == "get_resource":
        kind = str(arguments.get("kind") or "").lower()
        name = str(arguments.get("name") or "")
        for item in inventory:
            if str(item.get("kind") or "").lower() == kind and item.get("name") == name and (not namespace or item.get("namespace") in {None, namespace}):
                return {"coverage": "native-discovery", "resource": item}
        raise HTTPException(status_code=404, detail="native resource not found in bounded discovery inventory")

    if tool == "search":
        query = str(arguments.get("query") or "").strip().lower()
        if not query:
            raise HTTPException(status_code=422, detail="native search requires a non-empty query")
        tokens = [token for token in query.split() if token]
        limit = min(int(arguments.get("limit") or 100), 200)
        matches = []
        for item in inventory:
            haystack = json.dumps(item, sort_keys=True).lower()
            if all(token in haystack for token in tokens):
                matches.append(item)
                if len(matches) >= limit:
                    break
        return {"coverage": "native-bounded-search", "items": matches, "count": len(matches)}

    if tool == "issues":
        issues = []
        for item in inventory:
            status = item.get("status") or {}
            desired = status.get("replicas")
            ready = status.get("readyReplicas", status.get("numberReady"))
            if isinstance(desired, int) and isinstance(ready, int) and ready < desired:
                issues.append({"severity": "warning", "kind": item.get("kind"), "namespace": item.get("namespace"), "name": item.get("name"), "summary": f"{ready}/{desired} replicas ready"})
            if str(item.get("kind") or "").lower() == "node":
                conditions = status.get("conditions") or []
                ready_condition = next((c for c in conditions if isinstance(c, dict) and c.get("type") == "Ready"), None)
                if ready_condition and ready_condition.get("status") != "True":
                    issues.append({"severity": "critical", "kind": "Node", "name": item.get("name"), "summary": "Node is not Ready"})
        return {"coverage": "native-bounded-health", "items": issues[:200], "count": len(issues)}

    if tool == "get_topology":
        nodes = []
        edges = []
        namespace_ids: set[str] = set()
        for item in inventory:
            rid = f"{item.get('kind')}:{item.get('namespace') or '_cluster'}:{item.get('name')}"
            nodes.append({"id": rid, "kind": item.get("kind"), "namespace": item.get("namespace"), "name": item.get("name")})
            if item.get("namespace"):
                nsid = f"Namespace:_cluster:{item['namespace']}"
                namespace_ids.add(nsid)
                edges.append({"from": rid, "to": nsid, "relationship": "in-namespace"})
        existing = {node["id"] for node in nodes}
        for nsid in sorted(namespace_ids - existing):
            nodes.append({"id": nsid, "kind": "Namespace", "namespace": None, "name": nsid.rsplit(":", 1)[-1]})
        return {"coverage": "native-inventory-topology", "nodes": nodes[:1000], "edges": edges[:2000]}

    raise HTTPException(status_code=501, detail=f"native Hermes fallback is not implemented for Radar tool {tool}")


async def _query_native_intelligence(cluster: dict[str, Any], payload: RadarIntelligenceQuery) -> dict[str, Any]:
    with closing(db.connect()) as conn:
        snapshot = _native_kubernetes_target(conn, cluster, payload.native_target_id)
    discovery = await kubernetes_broker.post("/v1/discover", {"target_snapshot": snapshot})
    return _native_intelligence_result(payload.tool, payload.arguments, discovery)


@app.post("/v1/clusters/{cluster_id}/intelligence/query")
async def query_cluster_intelligence(cluster_id: str, payload: RadarIntelligenceQuery, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    try:
        radar_provider.validate_read_tool(payload.tool, payload.arguments)
    except radar_provider.RadarProtocolError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    with closing(db.connect()) as conn:
        cluster = _cluster_dict(_get_cluster(conn, cluster_id))

    radar_error: str | None = None
    if payload.mode != "NATIVE":
        try:
            with closing(db.connect()) as conn:
                integration = _configured_radar_integration(conn, cluster, payload.integration_id)
            result = await radar_provider.query(
                integration["endpoint"],
                payload.tool,
                payload.arguments,
                timeout=float(os.getenv("HERMES_RADAR_TIMEOUT_SECONDS", "10")),
            )
            with closing(db.connect()) as conn:
                db.audit(conn, "radar.intelligence.queried", "admin", "cluster", cluster_id, {"mode": payload.mode, "tool": payload.tool, "provider": "radar", "integration_id": integration["id"], "argument_keys": sorted(payload.arguments)})
                conn.commit()
            return {"cluster_id": cluster_id, "mode": payload.mode, "provider": "radar", "fallback": False, "integration_id": integration["id"], "data": result}
        except HTTPException as exc:
            if payload.mode == "RADAR":
                raise
            radar_error = str(exc.detail)
        except radar_provider.RadarError as exc:
            if payload.mode == "RADAR":
                raise HTTPException(status_code=502, detail=str(exc)) from exc
            radar_error = str(exc)

    try:
        native = await _query_native_intelligence(cluster, payload)
    except HTTPException as exc:
        if payload.mode == "AUTO" and radar_error:
            raise HTTPException(status_code=503, detail={"radar": radar_error, "native": exc.detail}) from exc
        raise
    except Exception as exc:
        if payload.mode == "AUTO" and radar_error:
            raise HTTPException(status_code=503, detail={"radar": radar_error, "native": type(exc).__name__}) from exc
        raise

    with closing(db.connect()) as conn:
        db.audit(conn, "kubernetes.intelligence.native_queried", "admin", "cluster", cluster_id, {"mode": payload.mode, "tool": payload.tool, "provider": "native", "native_target_id": payload.native_target_id, "radar_fallback": bool(radar_error), "argument_keys": sorted(payload.arguments)})
        conn.commit()
    return {"cluster_id": cluster_id, "mode": payload.mode, "provider": "native", "fallback": bool(radar_error), "radar_error": radar_error, "native_target_id": payload.native_target_id, "data": radar_provider.redact(native)}


@app.post("/v1/clusters/{cluster_id}/intelligence/radar", status_code=201)
def record_radar_snapshot(cluster_id: str, payload: RadarSnapshotCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    summary = payload.model_dump()
    _validate_credential_metadata(summary)
    with closing(db.connect()) as conn:
        _get_cluster(conn, cluster_id)
        now = int(time.time())
        cur = conn.execute("INSERT INTO kubernetes_intelligence_snapshots (cluster_id,provider,observed_at,summary_json,created_at) VALUES (?,?,?,?,?)", (cluster_id, "radar", payload.observed_at, json.dumps(summary, sort_keys=True), now))
        snapshot_id = int(cur.lastrowid)
        db.audit(conn, "radar.snapshot_recorded", "admin", "cluster", cluster_id, {"snapshot_id": snapshot_id, "health_score": payload.health_score})
        conn.commit()
    return {"id": snapshot_id, "cluster_id": cluster_id, "provider": "radar", "summary": summary, "contract": cluster_factory.RADAR_CONTRACT}


def _persist_hubble_batch(conn, cluster_id: str, batch: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    observed_at = int(batch.get("observed_at") or time.time())
    events = batch.get("events") if isinstance(batch.get("events"), list) else []
    inserted: list[dict[str, Any]] = []
    now = int(time.time())
    allowed_event_keys = {"time", "verdict", "source", "destination", "protocol", "destination_port", "http", "drop_reason", "traffic_direction", "is_reply", "fingerprint"}
    allowed_endpoint_keys = {"namespace", "workload"}
    allowed_http_keys = {"method", "status_class"}
    for event in events[:200]:
        if not isinstance(event, dict) or set(event) - allowed_event_keys:
            continue
        fingerprint = str(event.get("fingerprint") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            continue
        source = event.get("source")
        destination = event.get("destination")
        http = event.get("http")
        if not isinstance(source, dict) or set(source) - allowed_endpoint_keys:
            continue
        if not isinstance(destination, dict) or set(destination) - allowed_endpoint_keys:
            continue
        if http is not None and (not isinstance(http, dict) or set(http) - allowed_http_keys):
            continue
        # Re-serialize only the exact sanitized schema accepted from the broker.
        normalized = {key: event.get(key) for key in allowed_event_keys}
        cur = conn.execute(
            "INSERT OR IGNORE INTO hubble_flow_events (cluster_id,observed_at,fingerprint,event_json,created_at) VALUES (?,?,?,?,?)",
            (cluster_id, observed_at, fingerprint, json.dumps(normalized, sort_keys=True), now),
        )
        if cur.rowcount:
            inserted.append(normalized)
    conn.execute(
        "DELETE FROM hubble_flow_events WHERE cluster_id=? AND id NOT IN (SELECT id FROM hubble_flow_events WHERE cluster_id=? ORDER BY observed_at DESC,id DESC LIMIT 2000)",
        (cluster_id, cluster_id),
    )
    summary = batch.get("summary") if isinstance(batch.get("summary"), dict) else {}
    if summary:
        conn.execute(
            "INSERT INTO kubernetes_intelligence_snapshots (cluster_id,provider,observed_at,summary_json,created_at) VALUES (?,?,?,?,?)",
            (cluster_id, "hubble", observed_at, json.dumps(summary, sort_keys=True), now),
        )
    return inserted, observed_at


async def _collect_hubble_live(cluster: dict[str, Any], payload: HubbleLiveQuery) -> dict[str, Any]:
    with closing(db.connect()) as conn:
        snapshot = _native_kubernetes_target(conn, cluster, payload.native_target_id)
    result = await kubernetes_broker.post(
        "/v1/hubble/collect",
        {"target_snapshot": snapshot, "last": payload.last, "since_seconds": payload.since_seconds},
    )
    if result.get("raw_flow_bodies_returned") is not False:
        raise HTTPException(status_code=502, detail="Kubernetes Broker did not attest sanitized Hubble output")
    return result


@app.post("/v1/clusters/{cluster_id}/network/live")
async def collect_cluster_network_live(cluster_id: str, payload: HubbleLiveQuery, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        cluster = _cluster_dict(_get_cluster(conn, cluster_id))
    batch = await _collect_hubble_live(cluster, payload)
    with closing(db.connect()) as conn:
        inserted, observed_at = _persist_hubble_batch(conn, cluster_id, batch)
        db.audit(conn, "hubble.live_collected", "admin", "cluster", cluster_id, {"target_id": payload.native_target_id, "received": len(batch.get("events") or []), "inserted": len(inserted), "observed_at": observed_at})
        conn.commit()
    return {"cluster_id": cluster_id, "provider": "cilium-hubble", "observed_at": observed_at, "events": inserted, "summary": batch.get("summary") or {}, "history_limit": 2000, "raw_flow_bodies_returned": False}


@app.get("/v1/clusters/{cluster_id}/network/history")
def get_cluster_network_history(cluster_id: str, limit: int = Query(default=100, ge=1, le=500), authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        _get_cluster(conn, cluster_id)
        rows = conn.execute("SELECT id,observed_at,event_json FROM hubble_flow_events WHERE cluster_id=? ORDER BY observed_at DESC,id DESC LIMIT ?", (cluster_id, limit)).fetchall()
    return {"cluster_id": cluster_id, "provider": "cilium-hubble", "events": [{"id": row["id"], "observed_at": row["observed_at"], **json.loads(row["event_json"])} for row in rows], "bounded": True, "max_stored_per_cluster": 2000}


@app.get("/v1/clusters/{cluster_id}/network/live/stream")
async def stream_cluster_network_live(
    cluster_id: str,
    request: Request,
    native_target_id: str = Query(min_length=1, max_length=160),
    last: int = Query(default=25, ge=1, le=100),
    since_seconds: int | None = Query(default=30, ge=1, le=3600),
    poll_seconds: float = Query(default=2.0, ge=1.0, le=30.0),
    authorization: str | None = Header(default=None),
):
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        cluster = _cluster_dict(_get_cluster(conn, cluster_id))
        _native_kubernetes_target(conn, cluster, native_target_id)

    async def event_stream():
        while True:
            if await request.is_disconnected():
                return
            try:
                payload = HubbleLiveQuery(native_target_id=native_target_id, last=last, since_seconds=since_seconds)
                batch = await _collect_hubble_live(cluster, payload)
                with closing(db.connect()) as conn:
                    inserted, observed_at = _persist_hubble_batch(conn, cluster_id, batch)
                    conn.commit()
                for event in inserted:
                    yield f"event: hubble-flow\ndata: {json.dumps({'cluster_id': cluster_id, 'observed_at': observed_at, 'flow': event}, sort_keys=True)}\n\n"
                if not inserted:
                    yield ": heartbeat\n\n"
            except HTTPException as exc:
                yield f"event: hubble-error\ndata: {json.dumps({'status': exc.status_code, 'detail': exc.detail}, sort_keys=True)}\n\n"
            await asyncio.sleep(poll_seconds)

    return StreamingResponse(event_stream(), media_type="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


DIAGNOSTIC_FORBIDDEN_EVIDENCE_KEYS = {
    "authorization", "body", "env", "environment", "headers", "kubeconfig",
    "password", "secret", "token", "url",
}


def _validate_diagnostic_evidence(value: Any, *, depth: int = 0) -> None:
    if depth > 8:
        raise HTTPException(status_code=502, detail="Kubernetes Broker diagnostic evidence is nested too deeply")
    if isinstance(value, dict):
        if len(value) > 128:
            raise HTTPException(status_code=502, detail="Kubernetes Broker diagnostic evidence object is too large")
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if normalized in DIAGNOSTIC_FORBIDDEN_EVIDENCE_KEYS:
                raise HTTPException(status_code=502, detail="Kubernetes Broker diagnostic evidence contains a forbidden sensitive field")
            _validate_diagnostic_evidence(child, depth=depth + 1)
    elif isinstance(value, list):
        if len(value) > 100:
            raise HTTPException(status_code=502, detail="Kubernetes Broker diagnostic evidence list is too large")
        for child in value:
            _validate_diagnostic_evidence(child, depth=depth + 1)
    elif isinstance(value, str) and len(value.encode("utf-8", errors="replace")) > 4000:
        raise HTTPException(status_code=502, detail="Kubernetes Broker diagnostic evidence string is too large")


async def _execute_cluster_diagnostics(*, cluster_id: str, native_target_id: str, checks: list[str], actor: str) -> tuple[dict[str, Any], dict[str, Any]]:
    with closing(db.connect()) as conn:
        cluster = _cluster_dict(_get_cluster(conn, cluster_id))
        snapshot = _native_kubernetes_target(conn, cluster, native_target_id)
    raw = await kubernetes_broker.post(
        "/v1/diagnostics/run",
        {"target_snapshot": snapshot, "checks": checks},
    )
    if len(json.dumps(raw, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > 512_000:
        raise HTTPException(status_code=502, detail="Kubernetes Broker diagnostic response exceeds 512 KiB")
    try:
        result = KubernetesDiagnosticsBrokerResult.model_validate(raw)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Kubernetes Broker returned malformed diagnostic data") from exc
    if set(result.summary) != {"PASS", "WARN", "FAIL", "SKIP"}:
        raise HTTPException(status_code=502, detail="Kubernetes Broker diagnostic summary schema is invalid")
    for finding in result.checks:
        _validate_diagnostic_evidence(finding.evidence)
    normalized = result.model_dump()
    with closing(db.connect()) as conn:
        db.audit(conn, "kubernetes.diagnostics.executed", actor, "cluster", cluster_id, {
            "target_id": native_target_id,
            "check_ids": [item["id"] for item in normalized["checks"]],
            "overall_status": normalized["overall_status"],
            "observed_at": normalized["observed_at"],
        })
        conn.commit()
    return cluster, {"cluster_id": cluster_id, "native_target_id": native_target_id, **normalized}


@app.post("/v1/clusters/{cluster_id}/diagnostics/run")
async def run_cluster_diagnostics(cluster_id: str, payload: KubernetesDiagnosticsQuery, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    _, result = await _execute_cluster_diagnostics(
        cluster_id=cluster_id, native_target_id=payload.native_target_id, checks=payload.checks, actor="admin"
    )
    return result


@app.post("/v1/clusters/{cluster_id}/verify", status_code=201)
async def run_cluster_unified_verification(cluster_id: str, payload: UnifiedVerificationQuery, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    try:
        selected = unified_verification.selected_checks(payload.checks)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    diagnostic_ids = unified_verification.diagnostic_check_ids(selected)
    cluster, diagnostics = await _execute_cluster_diagnostics(
        cluster_id=cluster_id,
        native_target_id=payload.native_target_id,
        checks=diagnostic_ids,
        actor="admin:unified-verification",
    )
    checks = unified_verification.from_diagnostics(diagnostics, selected)

    if "radar" in selected:
        integration = None
        try:
            with closing(db.connect()) as conn:
                integration = _configured_radar_integration(conn, cluster, payload.radar_integration_id)
        except HTTPException as exc:
            if payload.radar_integration_id is not None or exc.status_code != 503:
                raise
        if integration is not None:
            try:
                health = await radar_provider.health(integration["endpoint"])
                _validate_diagnostic_evidence(health)
                unified_verification.replace_check(checks, {
                    "id": "radar",
                    "status": "PASS",
                    "summary": "Configured Radar MCP endpoint completed an active initialize/health exchange.",
                    "evidence": {"integration_id": integration["id"], "health": health},
                })
            except radar_provider.RadarError as exc:
                unified_verification.replace_check(checks, {
                    "id": "radar",
                    "status": "FAIL",
                    "summary": "Configured Radar integration failed its active MCP health exchange.",
                    "evidence": {"integration_id": integration["id"], "error_type": type(exc).__name__},
                })

    for check in checks:
        _validate_diagnostic_evidence(check.get("evidence") or {})
    overall = unified_verification.overall_status(checks)
    observed_at = int(diagnostics.get("observed_at") or time.time())
    result_id = f"ver_{uuid.uuid4().hex[:16]}"
    evidence = {
        "source": "hermes-active-unified-verification",
        "native_target_id": payload.native_target_id,
        "requested_checks": selected,
        "diagnostic_check_ids": diagnostic_ids,
        "mutation_commands_executed": False,
        "credential_material_returned": False,
        "unsupported_probes_report_skip": True,
    }
    with closing(db.connect()) as conn:
        conn.execute(
            "INSERT INTO verification_results (id,operation_plan_id,changeset_id,subject_type,subject_id,status,checks_json,evidence_json,observed_at,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (result_id, None, None, "cluster", cluster_id, overall, json.dumps(checks, sort_keys=True), json.dumps(evidence, sort_keys=True), observed_at, int(time.time())),
        )
        db.audit(conn, "verification.active.executed", "admin", "verification", result_id, {
            "cluster_id": cluster_id,
            "target_id": payload.native_target_id,
            "status": overall,
            "check_ids": [check["id"] for check in checks],
        })
        conn.commit()
        row = conn.execute("SELECT * FROM verification_results WHERE id=?", (result_id,)).fetchone()
    return _verification_result_dict(row)


@app.post("/v1/clusters/{cluster_id}/intelligence/hubble", status_code=201)
def record_hubble_summary(cluster_id: str, payload: HubbleFlowSummaryCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    if payload.window_end < payload.window_start:
        raise HTTPException(status_code=422, detail="Hubble window_end must be >= window_start")
    summary = payload.model_dump()
    _validate_credential_metadata(summary)
    with closing(db.connect()) as conn:
        _get_cluster(conn, cluster_id)
        now = int(time.time())
        cur = conn.execute("INSERT INTO kubernetes_intelligence_snapshots (cluster_id,provider,observed_at,summary_json,created_at) VALUES (?,?,?,?,?)", (cluster_id, "hubble", payload.window_end, json.dumps(summary, sort_keys=True), now))
        snapshot_id = int(cur.lastrowid)
        db.audit(conn, "hubble.summary_recorded", "admin", "cluster", cluster_id, {"snapshot_id": snapshot_id, "window_start": payload.window_start, "window_end": payload.window_end})
        conn.commit()
    return {"id": snapshot_id, "cluster_id": cluster_id, "provider": "hubble", "summary": summary, "contract": cluster_factory.HUBBLE_CONTRACT}


@app.get("/v1/clusters/{cluster_id}/intelligence")
def get_cluster_intelligence(cluster_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        _get_cluster(conn, cluster_id)
        latest: dict[str, Any] = {}
        for provider in ("radar", "hubble"):
            row = conn.execute("SELECT * FROM kubernetes_intelligence_snapshots WHERE cluster_id=? AND provider=? ORDER BY observed_at DESC,id DESC LIMIT 1", (cluster_id, provider)).fetchone()
            latest[provider] = None if not row else {"id": row["id"], "observed_at": row["observed_at"], "summary": json.loads(row["summary_json"] or "{}")}
    return {"cluster_id": cluster_id, "radar_contract": cluster_factory.RADAR_CONTRACT, "hubble_contract": cluster_factory.HUBBLE_CONTRACT, "latest": latest, "diagnostics": cluster_factory.NATIVE_DIAGNOSTICS}


# --- 0.5.11-dev.4 Full Operations Center + next-deploy infrastructure ---

def _fleet_entry(conn, cluster_row: Any) -> dict[str, Any]:
    cluster = _cluster_dict(cluster_row)
    profile = _profile_dict(_get_profile(conn, cluster["profile_id"]))
    servers = [_server_dict(_get_server(conn, server_id)) for server_id in profile["server_ids"]]
    sites = sorted({item["site"] for item in servers if item.get("site")})
    zones = sorted({item["zone"] for item in servers if item.get("zone")})
    latest_radar = conn.execute(
        "SELECT summary_json,observed_at FROM kubernetes_intelligence_snapshots WHERE cluster_id=? AND provider='radar' ORDER BY observed_at DESC,id DESC LIMIT 1",
        (cluster["id"],),
    ).fetchone()
    health = "UNKNOWN"
    radar_score = None
    if cluster["state"] == "READY":
        health = "HEALTHY"
    elif cluster["state"] in {"ERROR", "FAILED"}:
        health = "DEGRADED"
    if latest_radar:
        radar = json.loads(latest_radar["summary_json"] or "{}")
        radar_score = radar.get("health_score")
        if isinstance(radar_score, int):
            health = "HEALTHY" if radar_score >= 80 else "DEGRADED"
    return {
        **cluster,
        "sites": sites,
        "zones": zones,
        "health": health,
        "radar_health_score": radar_score,
        "agent_connectivity": "configured" if servers and all(item["connection_mode"] == "agent" for item in servers) else "mixed-or-direct",
        "provider_health": "contract-available" if cluster["provider"] in cluster_factory.CLUSTER_PROVIDERS else "UNKNOWN",
    }


def _select_fleet_targets(conn, selector: dict[str, Any]) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM clusters WHERE status='configured' ORDER BY id").fetchall()
    selected: list[dict[str, Any]] = []
    for row in rows:
        entry = _fleet_entry(conn, row)
        if selector.get("cluster_ids") and entry["id"] not in selector["cluster_ids"]:
            continue
        if selector.get("environment_ids") and entry["environment_id"] not in selector["environment_ids"]:
            continue
        if selector.get("providers") and entry["provider"] not in selector["providers"]:
            continue
        if selector.get("states") and entry["state"] not in selector["states"]:
            continue
        if selector.get("sites") and not set(selector["sites"]).intersection(entry["sites"]):
            continue
        if selector.get("zones") and not set(selector["zones"]).intersection(entry["zones"]):
            continue
        labels = entry.get("labels") or {}
        if any(labels.get(key) != value for key, value in (selector.get("labels") or {}).items()):
            continue
        selected.append(_cluster_snapshot(conn, entry["id"]))
    return selected


def _store_fleet_target_snapshot(conn, selector: dict[str, Any], targets: list[dict[str, Any]]) -> str:
    fleet_id = f"flt_{uuid.uuid4().hex[:16]}"
    target_refs = [{"id": item["id"], "snapshot_hash": item["snapshot_hash"]} for item in targets]
    snapshot_hash = sha256_hex({"selector": selector, "targets": target_refs})
    conn.execute(
        "INSERT INTO fleet_target_snapshots (id,selector_json,targets_json,snapshot_hash,status,created_at) VALUES (?,?,?,?,?,?)",
        (fleet_id, json.dumps(selector, sort_keys=True), json.dumps(target_refs, sort_keys=True), snapshot_hash, "configured", int(time.time())),
    )
    return fleet_id


def _store_operation_plan(
    conn,
    *,
    typed_plan: dict[str, Any],
    subject_type: str,
    subject_id: str,
    changeset: Any,
    requested_by: str,
    executor: str,
) -> tuple[Any, Any]:
    now = int(time.time())
    plan_id = f"opn_{uuid.uuid4().hex[:16]}"
    job_id = f"opj_{uuid.uuid4().hex[:16]}"
    conn.execute(
        "INSERT INTO operation_plans (id,kind,subject_type,subject_id,state,changeset_id,plan_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (plan_id, typed_plan["kind"], subject_type, subject_id, "WAITING_APPROVAL" if changeset["approval_required"] else "PLANNED", changeset["id"], json.dumps(typed_plan, sort_keys=True), now, now),
    )
    conn.execute(
        "INSERT INTO operation_jobs (id,operation_plan_id,changeset_id,executor,state,stage,plan_hash,request_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (job_id, plan_id, changeset["id"], executor, "WAITING_APPROVAL", "plan", changeset["plan_hash"], json.dumps({"typed_plan_hash": typed_plan["plan_hash"], "subject_id": subject_id}, sort_keys=True), now, now),
    )
    db.audit(conn, "operation_plan.created", requested_by, "operation_plan", plan_id, {"changeset_id": changeset["id"], "operation_job_id": job_id, "typed_plan_hash": typed_plan["plan_hash"], "executor": executor})
    return conn.execute("SELECT * FROM operation_plans WHERE id=?", (plan_id,)).fetchone(), conn.execute("SELECT * FROM operation_jobs WHERE id=?", (job_id,)).fetchone()


def _plan_mutation(
    conn,
    *,
    typed_plan: dict[str, Any],
    target_id: str,
    subject_type: str,
    subject_id: str,
    requested_by: str,
    source_channel: str,
    adapter: str,
    ttl_seconds: int,
    executor: str,
) -> dict[str, Any]:
    operation = typed_plan["operation"]
    changeset = _insert_changeset(
        conn,
        operation=operation if ".apply" in operation or ".upgrade" in operation or ".remove" in operation or ".delete" in operation or ".restart" in operation or ".scale" in operation else f"{operation}.apply",
        adapter=adapter,
        target_id=target_id,
        requested_by=requested_by,
        source_channel=source_channel,
        source_revision=None,
        parameters={"resource_type": typed_plan["kind"], "typed_plan": typed_plan},
        policy_generation=db.get_policy_generation(conn),
        ttl_seconds=ttl_seconds,
    )
    preview = {
        "summary": f"Governed {typed_plan['operation']} plan for {subject_type} {subject_id}",
        "details": typed_plan,
        "source": "operations-center-deterministic-planner",
    }
    conn.execute("UPDATE changesets SET preview_json=?,state='PREVIEWED',updated_at=? WHERE id=?", (json.dumps(preview, sort_keys=True), int(time.time()), changeset["id"]))
    changeset = conn.execute("SELECT * FROM changesets WHERE id=?", (changeset["id"],)).fetchone()
    plan_row, job_row = _store_operation_plan(
        conn,
        typed_plan=typed_plan,
        subject_type=subject_type,
        subject_id=subject_id,
        changeset=changeset,
        requested_by=requested_by,
        executor=executor,
    )
    return {"operation_plan": _operation_plan_dict(plan_row), "changeset": _changeset_dict(changeset), "operation_job": _operation_job_dict(job_row)}


def _operation_job_bound_plan(conn, job: Any, *, require_current_policy: bool) -> tuple[Any, dict[str, Any], dict[str, Any], dict[str, Any]]:
    changeset = _changeset(conn, job["changeset_id"])
    if require_current_policy:
        _require_current_policy_generation(conn, changeset)
    changeset_plan = json.loads(changeset["plan_json"] or "{}")
    if sha256_hex(changeset_plan) != changeset["plan_hash"]:
        raise HTTPException(status_code=409, detail="stored ChangeSet hash verification failed")
    if changeset["plan_hash"] != job["plan_hash"]:
        raise HTTPException(status_code=409, detail="operation job exact plan hash no longer matches ChangeSet")
    plan_row = conn.execute("SELECT * FROM operation_plans WHERE id=?", (job["operation_plan_id"],)).fetchone()
    if not plan_row:
        raise HTTPException(status_code=409, detail="operation job references missing operation plan")
    if plan_row["changeset_id"] != changeset["id"]:
        raise HTTPException(status_code=409, detail="operation plan ChangeSet binding mismatch")
    typed_plan = json.loads(plan_row["plan_json"] or "{}")
    typed_hash = typed_plan.get("plan_hash")
    unhashed_typed_plan = dict(typed_plan)
    unhashed_typed_plan.pop("plan_hash", None)
    if not typed_hash or sha256_hex(unhashed_typed_plan) != typed_hash:
        raise HTTPException(status_code=409, detail="operation typed plan hash verification failed")
    bound_typed_plan = ((changeset_plan.get("parameters") or {}).get("typed_plan") or {})
    if bound_typed_plan != typed_plan:
        raise HTTPException(status_code=409, detail="operation plan is not exactly bound to the ChangeSet plan")
    request = json.loads(job["request_json"] or "{}")
    if request.get("typed_plan_hash") != typed_hash:
        raise HTTPException(status_code=409, detail="operation job typed plan hash binding mismatch")
    return changeset, changeset_plan, typed_plan, request


def _valid_operation_approval_ids(conn, changeset: Any, *, now: int) -> list[str]:
    if not changeset["approval_required"]:
        return []
    required_approvals = 2 if changeset["risk"] == "CRITICAL" else 1
    approval_rows = conn.execute(
        "SELECT * FROM approvals WHERE changeset_id=? AND plan_hash=? AND status='APPROVED' AND consumed_at IS NULL ORDER BY issued_at ASC,id ASC",
        (changeset["id"], changeset["plan_hash"]),
    ).fetchall()
    valid_by_approver: dict[str, Any] = {}
    for approval in approval_rows:
        if approval["approver"] not in valid_by_approver and _approval_is_valid(approval, changeset=changeset, now=now):
            valid_by_approver[approval["approver"]] = approval
    if len(valid_by_approver) < required_approvals:
        raise HTTPException(status_code=409, detail=f"{required_approvals} valid distinct integrity-checked approval(s) required for this exact operation plan hash")
    return [str(item["id"]) for item in list(valid_by_approver.values())[:required_approvals]]


def _verify_operation_job_authorization(conn, job: Any) -> tuple[Any, dict[str, Any], dict[str, Any], list[str]]:
    now = int(time.time())
    changeset, changeset_plan, typed_plan, _ = _operation_job_bound_plan(conn, job, require_current_policy=True)
    required_state = "APPROVED" if changeset["approval_required"] else "PREVIEWED"
    if changeset["state"] != required_state:
        raise HTTPException(status_code=409, detail=f"operation job requires ChangeSet state {required_state}")
    current_changeset_target = _target_snapshot(conn, changeset["target_id"])
    if current_changeset_target != changeset_plan.get("target_snapshot"):
        raise HTTPException(status_code=409, detail=f"target drift detected for {changeset['target_id']}; re-plan and re-approve")
    for target in typed_plan.get("targets", []):
        target_id = target.get("id")
        expected = target.get("snapshot_hash")
        if not target_id or not expected:
            continue
        current = _target_snapshot(conn, target_id)
        if current.get("snapshot_hash") != expected:
            raise HTTPException(status_code=409, detail=f"target drift detected for {target_id}; re-plan and re-approve")
    provider = typed_plan.get("provider") if isinstance(typed_plan.get("provider"), dict) else {}
    if provider.get("kind") == "pxe":
        desired = typed_plan.get("desired_state") if isinstance(typed_plan.get("desired_state"), dict) else {}
        role_bindings = desired.get("artifacts") if isinstance(desired.get("artifacts"), dict) else {}
        try:
            current_manifest = cluster_factory.resolve_pxe_artifact_manifest(
                role_bindings={str(role): str(artifact_id) for role, artifact_id in role_bindings.items()},
                artifacts=[_artifact_mirror_item_dict(row) for row in conn.execute("SELECT * FROM artifact_mirror_items ORDER BY id").fetchall()],
            )
            current_supply = cluster_factory.pxe_artifact_supply(current_manifest)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=f"PXE artifact manifest drifted or is no longer READY: {exc}") from exc
        expected_supply = typed_plan.get("artifact_supply") if isinstance(typed_plan.get("artifact_supply"), dict) else {}
        if current_supply.get("manifest_hash") != expected_supply.get("manifest_hash") or current_supply.get("supply_hash") != expected_supply.get("supply_hash"):
            raise HTTPException(status_code=409, detail="PXE artifact manifest drifted after planning; re-plan and re-approve")
    approval_ids = _valid_operation_approval_ids(conn, changeset, now=now)
    return changeset, changeset_plan, typed_plan, approval_ids


def _issue_operation_job_ticket(conn, job: Any, changeset: Any, changeset_plan: dict[str, Any], typed_plan: dict[str, Any], approval_ids: list[str]) -> tuple[dict[str, Any], str]:
    now = int(time.time())
    expiry_candidates = [int(changeset["expires_at"] or now + 120)]
    if approval_ids:
        placeholders = ",".join("?" for _ in approval_ids)
        rows = conn.execute(f"SELECT expires_at FROM approvals WHERE id IN ({placeholders})", approval_ids).fetchall()
        expiry_candidates.extend(int(row["expires_at"]) for row in rows)
    ttl_seconds = max(1, min(120, min(expiry_candidates) - now))
    preconditions = {
        "operation_job_id": job["id"],
        "operation_plan_id": job["operation_plan_id"],
        "executor": job["executor"],
        "typed_plan_hash": typed_plan["plan_hash"],
        "policy_generation": int(changeset["policy_generation"]),
    }
    try:
        ticket, signature = issue_ticket(
            changeset["id"],
            changeset["plan_hash"],
            changeset_plan,
            ttl_seconds=ttl_seconds,
            preconditions=preconditions,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    request = json.loads(job["request_json"] or "{}")
    request["authorization"] = {
        "ticket_hash": sha256_hex(ticket),
        "issued_at": ticket["issued_at"],
        "expires_at": ticket["expires_at"],
        "approval_ids": approval_ids,
        "policy_generation": int(changeset["policy_generation"]),
        "plan_hash": changeset["plan_hash"],
    }
    conn.execute("UPDATE operation_jobs SET request_json=?,updated_at=? WHERE id=?", (json.dumps(request, sort_keys=True), now, job["id"]))
    return ticket, signature


def _verify_operation_job_ticket(conn, job: Any, ticket: dict[str, Any], signature: str, *, require_fresh: bool) -> dict[str, Any]:
    changeset, changeset_plan, typed_plan, request = _operation_job_bound_plan(conn, job, require_current_policy=False)
    authorization = request.get("authorization") or {}
    if not authorization.get("ticket_hash"):
        raise HTTPException(status_code=409, detail="operation job has no issued execution ticket")
    try:
        verify_ticket(ticket, signature, require_fresh=require_fresh)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if sha256_hex(ticket) != authorization["ticket_hash"]:
        raise HTTPException(status_code=409, detail="execution ticket does not match the authorized operation job")
    if ticket.get("changeset_id") != changeset["id"] or ticket.get("plan_hash") != changeset["plan_hash"] or ticket.get("plan") != changeset_plan:
        raise HTTPException(status_code=409, detail="execution ticket ChangeSet binding mismatch")
    preconditions = ticket.get("preconditions") or {}
    expected = {
        "operation_job_id": job["id"],
        "operation_plan_id": job["operation_plan_id"],
        "executor": job["executor"],
        "typed_plan_hash": typed_plan["plan_hash"],
        "policy_generation": int(changeset["policy_generation"]),
    }
    if preconditions != expected:
        raise HTTPException(status_code=409, detail="execution ticket operation preconditions mismatch")
    return authorization


@app.get("/v1/operator-center/contracts")
def operator_center_contracts() -> dict[str, Any]:
    return operator_center.contracts()


@app.get("/v1/operations-center/contracts")
def operations_center_contracts() -> dict[str, Any]:
    return operations.contracts()


@app.get("/v1/operations-center/overview")
def operations_center_overview(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        fleet = [_fleet_entry(conn, row) for row in conn.execute("SELECT * FROM clusters WHERE status='configured' ORDER BY name").fetchall()]
        providers = [_infrastructure_provider_dict(row) for row in conn.execute("SELECT * FROM infrastructure_providers WHERE status='configured' ORDER BY name").fetchall()]
        artifacts = [_artifact_mirror_item_dict(row) for row in conn.execute("SELECT * FROM artifact_mirror_items WHERE status='configured' ORDER BY name").fetchall()]
        pending = conn.execute("SELECT COUNT(*) FROM operation_jobs WHERE state IN ('WAITING_APPROVAL','READY','RUNNING','PAUSED')").fetchone()[0]
        verification_failures = conn.execute("SELECT COUNT(*) FROM verification_results WHERE status='FAIL'").fetchone()[0]
    return {
        "fleet": fleet,
        "providers": providers,
        "artifacts": artifacts,
        "pending_operation_jobs": pending,
        "verification_failures": verification_failures,
        "credential_material_exposed": False,
        "mutation_backend": "shared-governed-intent-planner",
    }


@app.get("/v1/fleet/clusters")
def fleet_clusters(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        return [_fleet_entry(conn, row) for row in conn.execute("SELECT * FROM clusters WHERE status='configured' ORDER BY name").fetchall()]


@app.get("/v1/infrastructure-providers")
def list_infrastructure_providers(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM infrastructure_providers ORDER BY name").fetchall()
    return [_infrastructure_provider_dict(row) for row in rows]


@app.post("/v1/infrastructure-providers", status_code=201)
def create_infrastructure_provider(payload: InfrastructureProviderCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    _validate_credential_metadata(payload.capabilities)
    _reject_embedded_url_credentials(payload.endpoint, "provider endpoint")
    if payload.kind == "network-switch":
        try:
            operations.validate_network_switch_provider(payload.model_dump())
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    provider_id = f"ipr_{uuid.uuid4().hex[:16]}"
    now = int(time.time())
    with closing(db.connect()) as conn:
        cred = _get_credential_ref(conn, payload.credential_ref)
        if cred["status"] != "configured":
            raise HTTPException(status_code=409, detail="provider credential reference is not configured")
        try:
            conn.execute(
                "INSERT INTO infrastructure_providers (id,name,kind,endpoint,credential_ref,api_version,implementation_version,site,zone,capabilities_json,labels_json,status,health_status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (provider_id, payload.name, payload.kind, payload.endpoint, payload.credential_ref, payload.api_version, payload.implementation_version, payload.site, payload.zone, json.dumps(payload.capabilities, sort_keys=True), json.dumps(payload.labels, sort_keys=True), "configured", "UNKNOWN", now, now),
            )
        except Exception as exc:
            if "UNIQUE constraint failed" in str(exc):
                raise HTTPException(status_code=409, detail="infrastructure provider name already exists") from exc
            raise
        db.audit(conn, "infrastructure_provider.created", "admin", "infrastructure_provider", provider_id, {"kind": payload.kind, "api_version": payload.api_version, "implementation_version": payload.implementation_version, "credential_ref": payload.credential_ref})
        conn.commit()
        row = _get_infrastructure_provider(conn, provider_id)
    return _infrastructure_provider_dict(row)


@app.post("/v1/infrastructure-providers/{provider_id}/health")
def record_infrastructure_provider_health(provider_id: str, payload: InfrastructureProviderHealth, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    _validate_credential_metadata(payload.evidence)
    with closing(db.connect()) as conn:
        _get_infrastructure_provider(conn, provider_id)
        conn.execute("UPDATE infrastructure_providers SET health_status=?,health_detail=?,last_health_at=?,updated_at=? WHERE id=?", (payload.status, payload.detail, payload.observed_at, int(time.time()), provider_id))
        db.audit(conn, "infrastructure_provider.health_recorded", "admin", "infrastructure_provider", provider_id, {"status": payload.status, "observed_at": payload.observed_at, "evidence": payload.evidence})
        conn.commit()
        row = _get_infrastructure_provider(conn, provider_id)
    return _infrastructure_provider_dict(row)


@app.get("/v1/artifact-mirror/items")
def list_artifact_mirror_items(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM artifact_mirror_items ORDER BY name").fetchall()
    return [_artifact_mirror_item_dict(row) for row in rows]


@app.post("/v1/artifact-mirror/items", status_code=201)
def create_artifact_mirror_item(payload: ArtifactMirrorItemCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    _reject_embedded_url_credentials(payload.source, "artifact source")
    _reject_embedded_url_credentials(payload.destination, "artifact destination")
    artifact_id = f"art_{uuid.uuid4().hex[:16]}"
    now = int(time.time())
    with closing(db.connect()) as conn:
        try:
            conn.execute(
                "INSERT INTO artifact_mirror_items (id,name,kind,source,destination,version,digest,labels_json,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (artifact_id, payload.name, payload.kind, payload.source, payload.destination, payload.version, payload.digest, json.dumps(payload.labels, sort_keys=True), "configured", now, now),
            )
        except Exception as exc:
            if "UNIQUE constraint failed" in str(exc):
                raise HTTPException(status_code=409, detail="artifact mirror item name already exists") from exc
            raise
        db.audit(conn, "artifact_mirror_item.created", "admin", "artifact", artifact_id, {"kind": payload.kind, "version": payload.version, "digest": payload.digest})
        conn.commit()
        row = _get_artifact_mirror_item(conn, artifact_id)
    return _artifact_mirror_item_dict(row)


@app.get("/v1/operation-plans")
def list_operation_plans(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM operation_plans ORDER BY created_at DESC,id DESC").fetchall()
    return [_operation_plan_dict(row) for row in rows]


@app.get("/v1/operation-jobs")
def list_operation_jobs(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM operation_jobs ORDER BY created_at DESC,id DESC").fetchall()
    return [_operation_job_dict(row) for row in rows]


@app.post("/v1/operations-center/intents/plan", status_code=201)
async def plan_operations_intent(payload: OperationsIntentPlanCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    selector = payload.selector.model_dump()
    _validate_credential_metadata(payload.parameters)
    _validate_credential_metadata(payload.desired_state)
    if payload.domain == "read":
        _require_admin(authorization)
        try:
            query_plan = operations.read_query_plan(operation=payload.operation, selector=selector, parameters=payload.parameters)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"mode": "read", "query_plan": query_plan, "changeset": None, "operation_job": None}

    _require_bot(authorization)
    _require_bot_origin(payload.source_channel)
    with closing(db.connect()) as conn:
        if payload.domain == "day2":
            if not payload.target_id or not payload.target_id.startswith("clu_"):
                raise HTTPException(status_code=422, detail="day2 intent requires target_id for a cluster")
            cluster = _cluster_dict(_get_cluster(conn, payload.target_id))
            if cluster["state"] != "READY" and payload.operation not in {"cluster.template.clone", "cluster.disaster-recovery"}:
                raise HTTPException(status_code=409, detail="day-2 target cluster must be READY")
            target = _cluster_snapshot(conn, payload.target_id)
            targets = [target]
            executor = "cluster-provider-worker"
            adapter = "provider"
            runtime_preview = None
            artifact_supply = None
            if operations.kubernetes_day2_runtime_capable(payload.operation):
                try:
                    operations.validate_kubernetes_day2_parameters(payload.operation, payload.parameters)
                except ValueError as exc:
                    raise HTTPException(status_code=422, detail=str(exc)) from exc
                native_target = _native_kubernetes_target(conn, cluster, str(payload.parameters.get("native_target_id") or ""))
                targets.append(native_target)
                runtime_preview = await kubernetes_broker.post(
                    "/v1/day2/preview",
                    {"target_snapshot": native_target, "operation": payload.operation, "parameters": payload.parameters},
                )
                _validate_credential_metadata(runtime_preview)
                if runtime_preview.get("secret_output_suppressed") is not True or not isinstance(runtime_preview.get("preconditions"), dict) or not runtime_preview.get("preconditions"):
                    raise HTTPException(status_code=502, detail="Kubernetes Broker returned an unsafe or incomplete day-2 runtime preview")
                executor = "kubernetes-broker"
                adapter = "kubernetes"
            elif operations.provider_day2_runtime_capable(payload.operation):
                try:
                    operations.validate_provider_day2_parameters(payload.operation, payload.parameters)
                except ValueError as exc:
                    raise HTTPException(status_code=422, detail=str(exc)) from exc
                server_ids: list[str] = []
                for key in ("server_id", "old_server_id", "new_server_id"):
                    value = str(payload.parameters.get(key) or "")
                    if value and value not in server_ids:
                        server_ids.append(value)
                cluster_server_ids = {str(item.get("id") or "") for item in target.get("server_snapshots") or []}
                if payload.operation == "cluster.worker.add" and server_ids and server_ids[0] in cluster_server_ids:
                    raise HTTPException(status_code=409, detail="worker add server is already part of the cluster")
                if payload.operation == "cluster.worker.remove" and (not server_ids or server_ids[0] not in cluster_server_ids):
                    raise HTTPException(status_code=409, detail="worker remove server is not part of the cluster")
                if payload.operation == "cluster.worker.replace" and (payload.parameters.get("old_server_id") not in cluster_server_ids or payload.parameters.get("new_server_id") in cluster_server_ids):
                    raise HTTPException(status_code=409, detail="worker replace requires old server in cluster and new server outside cluster")
                if payload.operation == "cluster.node.maintenance" and (not server_ids or server_ids[0] not in cluster_server_ids):
                    raise HTTPException(status_code=409, detail="maintenance server is not part of the cluster")
                for server_id in server_ids:
                    targets.append(_server_snapshot(conn, server_id))
                if payload.operation == "cluster.decommission" and str(payload.parameters.get("confirm_cluster_name") or "") != cluster["name"]:
                    raise HTTPException(status_code=409, detail="decommission confirmation must exactly match cluster name")
                blueprint_id = str(payload.parameters.get("artifact_blueprint_id") or "")
                if blueprint_id:
                    candidate_blueprint = _blueprint_dict(_get_blueprint(conn, blueprint_id))
                    if candidate_blueprint["provider"] != cluster["provider"]:
                        raise HTTPException(status_code=409, detail="artifact blueprint provider does not match cluster provider")
                    if payload.operation == "cluster.kubernetes.upgrade" and candidate_blueprint["kubernetes_version"] != str(payload.parameters.get("target_version") or "").lstrip("v"):
                        requested = str(payload.parameters.get("target_version") or "").lstrip("v")
                        if candidate_blueprint["kubernetes_version"].lstrip("v") != requested:
                            raise HTTPException(status_code=409, detail="artifact blueprint Kubernetes version does not match target_version")
                    candidate_manifest = _blueprint_artifact_manifest(conn, blueprint_id)
                    try:
                        artifact_supply = cluster_factory.offline_artifact_supply(candidate_manifest)
                    except ValueError as exc:
                        raise HTTPException(status_code=409, detail=str(exc)) from exc
                else:
                    artifact_supply = target.get("artifact_supply")
                preliminary = operations.day2_plan(operation=payload.operation, targets=targets, parameters=payload.parameters, runtime_preview=None, artifact_supply=artifact_supply)
                runtime_preview = await provider_worker.post("/v1/provider/preview", {"changeset_plan": {"parameters": {"typed_plan": preliminary}}})
                _validate_credential_metadata(runtime_preview)
                if runtime_preview.get("secret_output_suppressed") is not True or runtime_preview.get("arbitrary_shell") is not False or runtime_preview.get("arbitrary_ssh_command") is not False:
                    raise HTTPException(status_code=502, detail="provider worker returned an unsafe runtime preview")
            try:
                typed_plan = operations.day2_plan(operation=payload.operation, targets=targets, parameters=payload.parameters, runtime_preview=runtime_preview, artifact_supply=artifact_supply)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            result = _plan_mutation(conn, typed_plan=typed_plan, target_id=payload.target_id, subject_type="cluster", subject_id=payload.target_id, requested_by=payload.requested_by, source_channel=payload.source_channel, adapter=adapter, ttl_seconds=payload.ttl_seconds, executor=executor)
        elif payload.domain == "fleet":
            targets = _select_fleet_targets(conn, selector)
            try:
                typed_plan = operations.fleet_plan(operation=payload.operation, selector=selector, targets=targets, parameters=payload.parameters)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            fleet_id = _store_fleet_target_snapshot(conn, selector, targets)
            result = _plan_mutation(conn, typed_plan=typed_plan, target_id=fleet_id, subject_type="fleet", subject_id=fleet_id, requested_by=payload.requested_by, source_channel=payload.source_channel, adapter="fleet", ttl_seconds=payload.ttl_seconds, executor="fleet-provider-worker")
        elif payload.domain in {"cloud", "bare-metal", "network"}:
            if not payload.provider_id:
                raise HTTPException(status_code=422, detail="infrastructure intent requires provider_id")
            provider = _infrastructure_provider_dict(_get_infrastructure_provider(conn, payload.provider_id))
            allowed_kinds = {
                "cloud": set(operations.CLOUD_PROVIDER_CONTRACTS),
                "bare-metal": set(operations.BARE_METAL_PROVIDER_CONTRACTS),
                "network": set(operations.NETWORK_PROVIDER_CONTRACTS),
            }[payload.domain]
            if provider["kind"] not in allowed_kinds:
                raise HTTPException(status_code=422, detail=f"provider kind {provider['kind']} does not match {payload.domain} domain")
            provider_snapshot = _infrastructure_provider_snapshot(conn, payload.provider_id)
            subject_targets: list[dict[str, Any]] = []
            artifact_supply = None
            if provider["kind"] == "pxe":
                capabilities = provider.get("capabilities") if isinstance(provider.get("capabilities"), dict) else {}
                if capabilities.get("network_scope") != "private-offline":
                    raise HTTPException(status_code=409, detail="PXE controller must declare private-offline network_scope")
                if capabilities.get("artifact_delivery") != "shared-readonly-mirror":
                    raise HTTPException(status_code=409, detail="PXE controller must declare shared-readonly-mirror artifact_delivery")
                if not payload.target_id or not payload.target_id.startswith("srv_"):
                    raise HTTPException(status_code=422, detail="PXE provisioning requires target_id for a registered server")
                server_snapshot = _server_snapshot(conn, payload.target_id)
                labels = server_snapshot.get("labels") if isinstance(server_snapshot.get("labels"), dict) else {}
                if not server_snapshot.get("provisioning_ip"):
                    raise HTTPException(status_code=409, detail="PXE target server requires a provisioning_ip")
                provisioning_mac = str(labels.get("provisioning_mac") or "")
                provisioning_nic = str(labels.get("provisioning_nic") or "")
                if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", provisioning_mac):
                    raise HTTPException(status_code=409, detail="PXE target server requires canonical lowercase provisioning_mac label")
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}", provisioning_nic):
                    raise HTTPException(status_code=409, detail="PXE target server requires a bounded provisioning_nic label")
                boot_provider_id = str(labels.get("boot_provider_id") or "")
                if not boot_provider_id.startswith("ipr_"):
                    raise HTTPException(status_code=409, detail="PXE target server requires a boot_provider_id label")
                boot_provider = _infrastructure_provider_dict(_get_infrastructure_provider(conn, boot_provider_id))
                if boot_provider["kind"] not in {"redfish", "ipmi"} or not operations.infrastructure_runtime_operation_capable(boot_provider["kind"], "boot.set"):
                    raise HTTPException(status_code=409, detail="PXE boot_provider_id must reference a trusted Redfish/IPMI boot runtime")
                if boot_provider["status"] != "configured":
                    raise HTTPException(status_code=409, detail="PXE boot provider is not configured")
                if payload.operation == "os.reimage" and str(payload.desired_state.get("confirm_server") or "") != server_snapshot["hostname"]:
                    raise HTTPException(status_code=409, detail="PXE reimage confirmation must exactly match the server hostname")
                role_bindings = payload.desired_state.get("artifacts") if isinstance(payload.desired_state.get("artifacts"), dict) else {}
                try:
                    pxe_manifest = cluster_factory.resolve_pxe_artifact_manifest(
                        role_bindings={str(role): str(artifact_id) for role, artifact_id in role_bindings.items()},
                        artifacts=[_artifact_mirror_item_dict(row) for row in conn.execute("SELECT * FROM artifact_mirror_items ORDER BY id").fetchall()],
                    )
                    artifact_supply = cluster_factory.pxe_artifact_supply(pxe_manifest)
                except ValueError as exc:
                    raise HTTPException(status_code=409, detail=str(exc)) from exc
                subject_targets.extend([server_snapshot, _infrastructure_provider_snapshot(conn, boot_provider_id)])
            elif payload.target_id:
                subject_targets.append(_target_snapshot(conn, payload.target_id))
            try:
                preliminary = operations.infrastructure_plan(
                    provider=provider, provider_snapshot=provider_snapshot, operation=payload.operation,
                    subject_targets=subject_targets, desired_state=payload.desired_state, runtime_preview=None,
                    artifact_supply=artifact_supply,
                )
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            runtime_preview = None
            executor = f"{provider['kind']}-provider-worker"
            if operations.infrastructure_runtime_operation_capable(provider["kind"], payload.operation):
                runtime_preview = await provider_worker.post(
                    "/v1/infrastructure/preview", {"changeset_plan": {"parameters": {"typed_plan": preliminary}}}
                )
                _validate_credential_metadata(runtime_preview)
                if (runtime_preview.get("secret_output_suppressed") is not True
                        or runtime_preview.get("credential_material_returned") is not False
                        or runtime_preview.get("arbitrary_cli") is not False
                        or runtime_preview.get("arbitrary_shell") is not False
                        or runtime_preview.get("active_probe") is not True):
                    raise HTTPException(status_code=502, detail="infrastructure provider worker returned an unsafe runtime preview")
                executor = "infrastructure-provider-worker"
            try:
                typed_plan = operations.infrastructure_plan(
                    provider=provider, provider_snapshot=provider_snapshot, operation=payload.operation,
                    subject_targets=subject_targets, desired_state=payload.desired_state, runtime_preview=runtime_preview,
                    artifact_supply=artifact_supply,
                )
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            adapter = {"cloud": "cloud", "bare-metal": "bare-metal", "network": "network"}[payload.domain]
            result = _plan_mutation(conn, typed_plan=typed_plan, target_id=payload.provider_id, subject_type="provider", subject_id=payload.provider_id, requested_by=payload.requested_by, source_channel=payload.source_channel, adapter=adapter, ttl_seconds=payload.ttl_seconds, executor=executor)
        elif payload.domain == "artifact":
            if not payload.target_id or not payload.target_id.startswith("art_"):
                raise HTTPException(status_code=422, detail="artifact intent requires target_id for an artifact mirror item")
            artifact_snapshot = _artifact_mirror_snapshot(conn, payload.target_id)
            try:
                typed_plan = operations.artifact_mirror_plan(artifact_snapshot=artifact_snapshot, parameters=payload.parameters)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            artifact_executor = "artifact-mirror-worker" if operations.artifact_mirror_runtime_capable(typed_plan) else "artifact-mirror-contract"
            result = _plan_mutation(conn, typed_plan=typed_plan, target_id=payload.target_id, subject_type="artifact", subject_id=payload.target_id, requested_by=payload.requested_by, source_channel=payload.source_channel, adapter="artifact", ttl_seconds=payload.ttl_seconds, executor=artifact_executor)
        else:
            raise HTTPException(status_code=422, detail="unsupported operations intent domain")
        conn.commit()
    return {"mode": "mutation", **result}


@app.post("/v1/operation-jobs/{job_id}/authorize")
def authorize_operation_job(job_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_bot(authorization)
    with closing(db.connect()) as conn:
        job = conn.execute("SELECT * FROM operation_jobs WHERE id=?", (job_id,)).fetchone()
        if not job:
            raise HTTPException(status_code=404, detail="operation job not found")
        if job["state"] not in {"WAITING_APPROVAL", "READY"}:
            raise HTTPException(status_code=409, detail="operation job cannot be authorized from its current state")
        changeset, changeset_plan, typed_plan, approval_ids = _verify_operation_job_authorization(conn, job)
        ticket, signature = _issue_operation_job_ticket(conn, job, changeset, changeset_plan, typed_plan, approval_ids)
        now = int(time.time())
        conn.execute("UPDATE operation_jobs SET state='READY',stage='authorized',updated_at=? WHERE id=?", (now, job_id))
        conn.execute("UPDATE operation_plans SET state='READY',updated_at=? WHERE id=?", (now, job["operation_plan_id"]))
        db.audit(conn, "operation_job.authorized", "hermes-bot", "operation_job", job_id, {
            "changeset_id": changeset["id"],
            "plan_hash": job["plan_hash"],
            "target_drift_check": "passed",
            "approval_ids": approval_ids,
            "execution_ticket_hash": sha256_hex(ticket),
            "execution_ticket_expires_at": ticket["expires_at"],
        })
        conn.commit()
        updated = conn.execute("SELECT * FROM operation_jobs WHERE id=?", (job_id,)).fetchone()
    result = _operation_job_dict(updated)
    result["execution_ticket"] = ticket
    result["signature"] = signature
    return result


def _persist_runtime_verification(conn, *, job: Any, changeset: Any, payload: dict[str, Any], actor: str, source: str = "kubernetes-broker") -> dict[str, Any]:
    verification = payload.get("verification") or {}
    checks = verification.get("checks") or []
    if not isinstance(checks, list) or not checks:
        raise HTTPException(status_code=502, detail=f"{source} returned no active verification checks")
    normalized: list[dict[str, Any]] = []
    for check in checks:
        if not isinstance(check, dict):
            raise HTTPException(status_code=502, detail=f"{source} returned malformed verification evidence")
        item = {
            "id": str(check.get("id") or "")[:160],
            "status": str(check.get("status") or ""),
            "summary": str(check.get("summary") or "")[:1000],
            "evidence": check.get("evidence") if isinstance(check.get("evidence"), dict) else {},
        }
        if not item["id"] or item["status"] not in {"PASS", "FAIL", "WARN", "SKIP"} or not item["summary"]:
            raise HTTPException(status_code=502, detail=f"{source} returned invalid typed verification fields")
        _validate_credential_metadata(item["evidence"])
        normalized.append(item)
    evidence = verification.get("evidence") if isinstance(verification.get("evidence"), dict) else {}
    _validate_credential_metadata(evidence)
    statuses = {item["status"] for item in normalized}
    overall = "FAIL" if "FAIL" in statuses else "WARN" if "WARN" in statuses else "SKIP" if statuses == {"SKIP"} else "PASS"
    result_id = f"ver_{uuid.uuid4().hex[:16]}"
    observed_at = int(verification.get("observed_at") or time.time())
    now = int(time.time())
    plan_row = conn.execute("SELECT subject_type,subject_id FROM operation_plans WHERE id=?", (job["operation_plan_id"],)).fetchone()
    if not plan_row:
        raise HTTPException(status_code=409, detail="operation plan disappeared before verification persistence")
    conn.execute(
        "INSERT INTO verification_results (id,operation_plan_id,changeset_id,subject_type,subject_id,status,checks_json,evidence_json,observed_at,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (result_id, job["operation_plan_id"], changeset["id"], plan_row["subject_type"], plan_row["subject_id"], overall, json.dumps(normalized, sort_keys=True), json.dumps(evidence, sort_keys=True), observed_at, now),
    )
    conn.execute("UPDATE operation_plans SET state=?,updated_at=? WHERE id=?", ("VERIFIED" if overall == "PASS" else "VERIFICATION_FAILED", now, job["operation_plan_id"]))
    db.audit(conn, "verification.runtime_recorded", actor, "verification", result_id, {"operation_plan_id": job["operation_plan_id"], "changeset_id": changeset["id"], "status": overall, "source": source})
    return {"id": result_id, "status": overall, "checks": normalized, "evidence": evidence, "observed_at": observed_at}


@app.post("/v1/operation-jobs/{job_id}/execute")
async def execute_operation_job(job_id: str, payload: OperationJobExecute, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_bot(authorization)
    with closing(db.connect()) as conn:
        job = conn.execute("SELECT * FROM operation_jobs WHERE id=?", (job_id,)).fetchone()
        if not job:
            raise HTTPException(status_code=404, detail="operation job not found")
        if job["state"] != "READY":
            raise HTTPException(status_code=409, detail="operation job must be READY before trusted execution")
        if job["executor"] not in {"kubernetes-broker", "artifact-mirror-worker", "cluster-provider-worker", "infrastructure-provider-worker"}:
            raise HTTPException(status_code=422, detail="operation job does not have a trusted runtime executor")
        changeset, _, typed_plan, current_approval_ids = _verify_operation_job_authorization(conn, job)
        ticket_auth = _verify_operation_job_ticket(conn, job, payload.execution_ticket, payload.signature, require_fresh=True)
        if set(ticket_auth.get("approval_ids") or []) != set(current_approval_ids):
            raise HTTPException(status_code=409, detail="execution ticket approvals no longer match current exact-plan authorization")
        if job["executor"] == "kubernetes-broker" and not operations.kubernetes_day2_runtime_capable(str(typed_plan.get("operation") or "")):
            raise HTTPException(status_code=422, detail="typed operation is not supported by the trusted Kubernetes day-2 runtime")
        if job["executor"] == "artifact-mirror-worker" and not operations.artifact_mirror_runtime_capable(typed_plan):
            raise HTTPException(status_code=422, detail="typed operation is not supported by the trusted artifact mirror runtime")
        if job["executor"] == "cluster-provider-worker" and not operations.provider_day2_runtime_capable(str(typed_plan.get("operation") or "")):
            raise HTTPException(status_code=422, detail="typed operation is not supported by the trusted cluster provider runtime")
        if job["executor"] == "infrastructure-provider-worker" and not operations.infrastructure_runtime_capable(typed_plan):
            raise HTTPException(status_code=422, detail="typed operation is not supported by the trusted infrastructure provider runtime")
        now = int(time.time())
        if current_approval_ids:
            placeholders = ",".join("?" for _ in current_approval_ids)
            changed = conn.execute(
                f"UPDATE approvals SET status='CONSUMED',consumed_at=?,decided_at=? WHERE id IN ({placeholders}) AND status='APPROVED' AND consumed_at IS NULL",
                (now, now, *current_approval_ids),
            )
            if changed.rowcount != len(current_approval_ids):
                raise HTTPException(status_code=409, detail="operation approval consumption race detected")
        conn.execute("UPDATE operation_jobs SET state='RUNNING',stage='execute',updated_at=? WHERE id=?", (now, job_id))
        conn.execute("UPDATE operation_plans SET state='RUNNING',updated_at=? WHERE id=?", (now, job["operation_plan_id"]))
        conn.execute("UPDATE changesets SET state='EXECUTING',updated_at=? WHERE id=?", (now, changeset["id"]))
        db.audit(conn, "operation_job.runtime_started", payload.actor, "operation_job", job_id, {"changeset_id": changeset["id"], "executor": job["executor"], "ticket_hash": ticket_auth["ticket_hash"]})
        conn.commit()
        executor = str(job["executor"])

    try:
        if executor == "kubernetes-broker":
            runtime_result = await kubernetes_broker.post("/v1/day2/execute", {"ticket": payload.execution_ticket, "signature": payload.signature})
        elif executor == "cluster-provider-worker":
            runtime_result = await provider_worker.post("/v1/provider/execute", {"ticket": payload.execution_ticket, "signature": payload.signature})
        elif executor == "infrastructure-provider-worker":
            runtime_result = await provider_worker.post("/v1/infrastructure/execute", {"ticket": payload.execution_ticket, "signature": payload.signature})
        else:
            runtime_result = await asyncio.to_thread(artifact_mirror.execute, typed_plan)
        _validate_credential_metadata(runtime_result)
    except HTTPException as exc:
        now = int(time.time())
        with closing(db.connect()) as conn:
            job = conn.execute("SELECT * FROM operation_jobs WHERE id=?", (job_id,)).fetchone()
            if job:
                changeset = _changeset(conn, job["changeset_id"])
                error = {"type": f"{executor}-error", "status_code": exc.status_code, "detail": exc.detail}
                conn.execute("UPDATE operation_jobs SET state='FAILED',stage='execute',result_json=?,updated_at=? WHERE id=?", (json.dumps(error, sort_keys=True), now, job_id))
                conn.execute("UPDATE operation_plans SET state='FAILED',updated_at=? WHERE id=?", (now, job["operation_plan_id"]))
                conn.execute("UPDATE changesets SET state='FAILED',executed_at=?,updated_at=? WHERE id=?", (now, now, changeset["id"]))
                db.audit(conn, "operation_job.runtime_failed", payload.actor, "operation_job", job_id, {"changeset_id": changeset["id"], "executor": executor, "error_type": "runtime"})
                conn.commit()
        raise

    now = int(time.time())
    with closing(db.connect()) as conn:
        job = conn.execute("SELECT * FROM operation_jobs WHERE id=?", (job_id,)).fetchone()
        if not job:
            raise HTTPException(status_code=409, detail="operation job disappeared during execution")
        changeset = _changeset(conn, job["changeset_id"])
        verification = _persist_runtime_verification(conn, job=job, changeset=changeset, payload=runtime_result, actor=payload.actor, source=executor)
        final_state = "SUCCEEDED" if verification["status"] == "PASS" else "FAILED"
        result = {"state": final_state, "stage": "verify", "runtime_result": runtime_result, "verification_id": verification["id"], "completed_at": now}
        conn.execute("UPDATE operation_jobs SET state=?,stage='verify',result_json=?,updated_at=? WHERE id=?", (final_state, json.dumps(result, sort_keys=True), now, job_id))
        conn.execute("UPDATE changesets SET state=?,execution_json=?,executed_at=?,updated_at=? WHERE id=?", ("EXECUTED" if final_state == "SUCCEEDED" else "FAILED", json.dumps(runtime_result, sort_keys=True), now, now, changeset["id"]))
        if executor == "artifact-mirror-worker":
            artifact_id = str((typed_plan.get("artifact") or {}).get("id") or "")
            if artifact_id:
                mirror_verification = {"verification_id": verification["id"], "status": verification["status"], "sync_state": "MIRRORED" if final_state == "SUCCEEDED" else "FAILED", "checks": verification["checks"], "observed_at": verification["observed_at"]}
                conn.execute("UPDATE artifact_mirror_items SET status='configured',verification_json=?,updated_at=? WHERE id=?", (json.dumps(mirror_verification, sort_keys=True), now, artifact_id))
        db.audit(conn, "operation_job.runtime_completed", payload.actor, "operation_job", job_id, {"changeset_id": changeset["id"], "executor": executor, "verification_id": verification["id"], "verification_status": verification["status"]})
        conn.commit()
        updated = conn.execute("SELECT * FROM operation_jobs WHERE id=?", (job_id,)).fetchone()
    response = {"operation_job": _operation_job_dict(updated), "verification": verification, "runtime_result": runtime_result}
    if executor == "kubernetes-broker":
        response["broker_result"] = runtime_result
    elif executor == "cluster-provider-worker":
        response["provider_worker_result"] = runtime_result
    elif executor == "infrastructure-provider-worker":
        response["infrastructure_worker_result"] = runtime_result
    return response


@app.post("/v1/operation-jobs/{job_id}/transition")
def transition_operation_job(job_id: str, payload: OperationJobTransition, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_bot(authorization)
    _validate_credential_metadata(payload.evidence)
    allowed = {
        "READY": {"RUNNING", "FAILED"},
        "RUNNING": {"RUNNING", "PAUSED", "SUCCEEDED", "FAILED"},
        "PAUSED": {"RUNNING", "FAILED"},
        "WAITING_APPROVAL": set(),
        "FAILED": set(),
        "SUCCEEDED": set(),
    }
    with closing(db.connect()) as conn:
        job = conn.execute("SELECT * FROM operation_jobs WHERE id=?", (job_id,)).fetchone()
        if not job:
            raise HTTPException(status_code=404, detail="operation job not found")
        if payload.state not in allowed.get(job["state"], set()):
            raise HTTPException(status_code=409, detail=f"operation job cannot transition from {job['state']} to {payload.state}")

        starting_execution = job["state"] == "READY" and payload.state == "RUNNING"
        if job["state"] == "READY":
            changeset, _, _, current_approval_ids = _verify_operation_job_authorization(conn, job)
            ticket_auth = _verify_operation_job_ticket(conn, job, payload.execution_ticket, payload.signature, require_fresh=True)
            authorized_approval_ids = list(ticket_auth.get("approval_ids") or [])
            if set(authorized_approval_ids) != set(current_approval_ids):
                raise HTTPException(status_code=409, detail="execution ticket approvals no longer match the current exact-plan authorization")
        else:
            changeset, _, _, _ = _operation_job_bound_plan(conn, job, require_current_policy=False)
            ticket_auth = _verify_operation_job_ticket(conn, job, payload.execution_ticket, payload.signature, require_fresh=False)
            authorized_approval_ids = list(ticket_auth.get("approval_ids") or [])
            if changeset["state"] != "EXECUTING":
                raise HTTPException(status_code=409, detail="operation job ChangeSet is not in EXECUTING state")

        now = int(time.time())
        if starting_execution:
            if authorized_approval_ids:
                placeholders = ",".join("?" for _ in authorized_approval_ids)
                changed = conn.execute(
                    f"UPDATE approvals SET status='CONSUMED',consumed_at=?,decided_at=? WHERE id IN ({placeholders}) AND status='APPROVED' AND consumed_at IS NULL",
                    (now, now, *authorized_approval_ids),
                )
                if changed.rowcount != len(authorized_approval_ids):
                    raise HTTPException(status_code=409, detail="operation approval consumption race detected")
            conn.execute("UPDATE changesets SET state='EXECUTING',updated_at=? WHERE id=?", (now, changeset["id"]))
        elif job["state"] == "READY" and payload.state == "FAILED":
            conn.execute("UPDATE changesets SET state='FAILED',updated_at=? WHERE id=?", (now, changeset["id"]))

        result_json = job["result_json"]
        if payload.state in {"SUCCEEDED", "FAILED"}:
            result_json = json.dumps({"state": payload.state, "stage": payload.stage, "message": payload.message, "evidence": payload.evidence, "completed_at": now}, sort_keys=True)
        conn.execute("UPDATE operation_jobs SET state=?,stage=?,result_json=?,updated_at=? WHERE id=?", (payload.state, payload.stage, result_json, now, job_id))
        plan_state = "SUCCEEDED" if payload.state == "SUCCEEDED" else "FAILED" if payload.state == "FAILED" else payload.state
        conn.execute("UPDATE operation_plans SET state=?,updated_at=? WHERE id=?", (plan_state, now, job["operation_plan_id"]))
        if job["state"] in {"RUNNING", "PAUSED"} and payload.state == "SUCCEEDED":
            conn.execute("UPDATE changesets SET state='EXECUTED',executed_at=?,updated_at=? WHERE id=?", (now, now, changeset["id"]))
        elif job["state"] in {"RUNNING", "PAUSED"} and payload.state == "FAILED":
            conn.execute("UPDATE changesets SET state='FAILED',executed_at=?,updated_at=? WHERE id=?", (now, now, changeset["id"]))
        db.audit(conn, "operation_job.transitioned", "hermes-bot", "operation_job", job_id, {
            "from": job["state"],
            "to": payload.state,
            "stage": payload.stage,
            "evidence": payload.evidence,
            "execution_ticket_hash": ticket_auth["ticket_hash"],
            "changeset_id": changeset["id"],
        })
        conn.commit()
        updated = conn.execute("SELECT * FROM operation_jobs WHERE id=?", (job_id,)).fetchone()
    return _operation_job_dict(updated)


@app.get("/v1/verifications")
def list_verifications(subject_id: str | None = None, authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        if subject_id:
            rows = conn.execute("SELECT * FROM verification_results WHERE subject_id=? ORDER BY observed_at DESC,created_at DESC", (subject_id,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM verification_results ORDER BY observed_at DESC,created_at DESC LIMIT 500").fetchall()
    return [_verification_result_dict(row) for row in rows]


@app.post("/v1/verifications", status_code=201)
def record_verification(payload: VerificationResultCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_bot(authorization)
    checks = [check.model_dump() for check in payload.checks]
    for check in checks:
        _validate_credential_metadata(check.get("evidence") or {})
    _validate_credential_metadata(payload.evidence)
    statuses = {check["status"] for check in checks}
    overall = "FAIL" if "FAIL" in statuses else "WARN" if "WARN" in statuses else "SKIP" if statuses == {"SKIP"} else "PASS"
    result_id = f"ver_{uuid.uuid4().hex[:16]}"
    now = int(time.time())
    with closing(db.connect()) as conn:
        if payload.operation_plan_id and not conn.execute("SELECT 1 FROM operation_plans WHERE id=?", (payload.operation_plan_id,)).fetchone():
            raise HTTPException(status_code=404, detail="operation plan not found")
        if payload.changeset_id:
            _changeset(conn, payload.changeset_id)
        conn.execute(
            "INSERT INTO verification_results (id,operation_plan_id,changeset_id,subject_type,subject_id,status,checks_json,evidence_json,observed_at,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (result_id, payload.operation_plan_id, payload.changeset_id, payload.subject_type, payload.subject_id, overall, json.dumps(checks, sort_keys=True), json.dumps(payload.evidence, sort_keys=True), payload.observed_at, now),
        )
        if payload.operation_plan_id:
            conn.execute("UPDATE operation_plans SET state=?,updated_at=? WHERE id=?", ("VERIFIED" if overall == "PASS" else "VERIFICATION_FAILED", now, payload.operation_plan_id))
        db.audit(conn, "verification.recorded", payload.actor, "verification", result_id, {"subject_type": payload.subject_type, "subject_id": payload.subject_id, "status": overall, "operation_plan_id": payload.operation_plan_id, "changeset_id": payload.changeset_id})
        conn.commit()
        row = conn.execute("SELECT * FROM verification_results WHERE id=?", (result_id,)).fetchone()
    return _verification_result_dict(row)
