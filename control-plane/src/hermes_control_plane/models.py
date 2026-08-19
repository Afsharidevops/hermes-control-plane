from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

RiskLevel = Literal["READ", "LOW", "HIGH", "CRITICAL"]
IntegrationKind = Literal["kubernetes", "docker", "swarm", "ssh", "github", "gitlab", "registry", "helm"]
ConnectionMode = Literal["direct", "agent"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EnvironmentCreate(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    slug: str | None = Field(default=None, min_length=1, max_length=80)
    risk_level: Literal["LOW", "HIGH", "CRITICAL"] = "LOW"
    labels: dict[str, str] = Field(default_factory=dict)


class EnvironmentUpdate(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    risk_level: Literal["LOW", "HIGH", "CRITICAL"] | None = None
    labels: dict[str, str] | None = None


class CredentialRefCreate(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    kind: Literal["kubeconfig", "ssh-key", "ssh-password", "token", "registry", "generic"]
    provider: str | None = Field(default=None, max_length=80)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CredentialRefUpdate(StrictModel):
    status: Literal["configured", "disabled", "rotating", "revoked"] | None = None
    metadata: dict[str, Any] | None = None




class CredentialRefSync(StrictModel):
    id: str = Field(pattern=r"^cred_[a-zA-Z0-9_-]{8,80}$")
    name: str = Field(min_length=1, max_length=120)
    kind: Literal["kubeconfig", "ssh-key", "ssh-password", "token", "registry", "generic"]
    provider: str = Field(min_length=1, max_length=80)
    status: Literal["configured", "disabled", "rotating", "revoked"] = "configured"
    metadata: dict[str, Any] = Field(default_factory=dict)


class CredentialRefRotate(StrictModel):
    actor: str = Field(min_length=1, max_length=160)
    metadata: dict[str, Any]


class AgentEnrollmentTokenCreate(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    ttl_seconds: int = Field(default=900, ge=60, le=86400)


class AgentEnroll(StrictModel):
    enrollment_token: str = Field(min_length=32, max_length=512)
    capabilities: list[str] = Field(default_factory=list, max_length=128)


class AgentHeartbeat(StrictModel):
    nonce: str = Field(min_length=16, max_length=256)
    capabilities: list[str] | None = Field(default=None, max_length=128)


class AgentRevoke(StrictModel):
    actor: str = Field(min_length=1, max_length=160)
    reason: str = Field(min_length=1, max_length=1000)


class AuditRetentionUpdate(StrictModel):
    actor: str = Field(min_length=1, max_length=160)
    days: int = Field(ge=1, le=3650)


class AuditPrune(StrictModel):
    actor: str = Field(min_length=1, max_length=160)


class IntegrationCreate(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    kind: IntegrationKind
    environment_id: str = Field(min_length=1, max_length=80)
    endpoint: str | None = Field(default=None, max_length=500)
    credential_ref: str | None = Field(default=None, max_length=120)
    connection_mode: ConnectionMode = "direct"
    allowed_scope: dict[str, Any] = Field(default_factory=dict)
    labels: dict[str, str] = Field(default_factory=dict)


class IntegrationUpdate(StrictModel):
    environment_id: str | None = Field(default=None, min_length=1, max_length=80)
    endpoint: str | None = Field(default=None, max_length=500)
    credential_ref: str | None = Field(default=None, max_length=120)
    connection_mode: ConnectionMode | None = None
    allowed_scope: dict[str, Any] | None = None
    labels: dict[str, str] | None = None
    status: Literal["configured", "disabled"] | None = None


class TargetCreate(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    kind: Literal["kubernetes", "docker", "swarm", "ssh", "git-project", "helm-target"]
    environment_id: str = Field(min_length=1, max_length=80)
    integration_id: str | None = Field(default=None, max_length=120)
    credential_ref: str | None = Field(default=None, max_length=120)
    connection_mode: ConnectionMode = "direct"
    address: str | None = Field(default=None, max_length=500)
    scope: dict[str, Any] = Field(default_factory=dict)
    labels: dict[str, str] = Field(default_factory=dict)


class TargetUpdate(StrictModel):
    environment_id: str | None = Field(default=None, min_length=1, max_length=80)
    integration_id: str | None = Field(default=None, max_length=120)
    credential_ref: str | None = Field(default=None, max_length=120)
    connection_mode: ConnectionMode | None = None
    address: str | None = Field(default=None, max_length=500)
    scope: dict[str, Any] | None = None
    labels: dict[str, str] | None = None
    status: Literal["configured", "disabled"] | None = None


class ChangeSetCreate(StrictModel):
    operation: str = Field(min_length=1, max_length=160)
    adapter: str = Field(min_length=1, max_length=80)
    target_id: str = Field(min_length=1, max_length=160)
    requested_by: str = Field(min_length=1, max_length=160)
    source_channel: Literal["ui", "telegram", "hermes-bot", "api", "cli"] = "api"
    source_revision: str | None = Field(default=None, max_length=256)
    parameters: dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: int = Field(default=900, ge=60, le=86400)


class PolicyGenerationBump(StrictModel):
    actor: str = Field(min_length=1, max_length=160)
    reason: str = Field(min_length=1, max_length=1000)


class PreviewCreate(StrictModel):
    summary: str = Field(min_length=1, max_length=2000)
    details: dict[str, Any] = Field(default_factory=dict)


class ApprovalDecision(StrictModel):
    approver: str = Field(min_length=1, max_length=160)
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    ttl_seconds: int = Field(default=300, ge=30, le=3600)


class RejectDecision(StrictModel):
    actor: str = Field(min_length=1, max_length=160)
    reason: str | None = Field(default=None, max_length=1000)


class ExecuteDecision(StrictModel):
    actor: str = Field(min_length=1, max_length=160)



class RollbackPlanCreate(StrictModel):
    requested_by: str = Field(min_length=1, max_length=160)
    source_channel: Literal["ui", "telegram", "hermes-bot", "api", "cli"] = "api"
    ttl_seconds: int = Field(default=900, ge=60, le=86400)


class ApplicationCreate(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    environment_id: str = Field(min_length=1, max_length=80)
    target_id: str = Field(min_length=1, max_length=160)
    source_repository: str = Field(min_length=1, max_length=500)
    revision_policy: str = Field(default="main", min_length=1, max_length=256)
    build_context: str = Field(default=".", min_length=1, max_length=500)
    image_repository: str | None = Field(default=None, max_length=500)
    deployment_type: Literal["kubernetes", "helm", "docker", "compose", "swarm", "gitops"]
    values_files: list[str] = Field(default_factory=list, max_length=64)
    verification_checks: list[dict[str, Any]] = Field(default_factory=list, max_length=64)
    rollback_strategy: dict[str, Any] = Field(default_factory=dict)
    labels: dict[str, str] = Field(default_factory=dict)


class ApplicationUpdate(StrictModel):
    environment_id: str | None = Field(default=None, min_length=1, max_length=80)
    target_id: str | None = Field(default=None, min_length=1, max_length=160)
    source_repository: str | None = Field(default=None, min_length=1, max_length=500)
    revision_policy: str | None = Field(default=None, min_length=1, max_length=256)
    build_context: str | None = Field(default=None, min_length=1, max_length=500)
    image_repository: str | None = Field(default=None, max_length=500)
    deployment_type: Literal["kubernetes", "helm", "docker", "compose", "swarm", "gitops"] | None = None
    values_files: list[str] | None = Field(default=None, max_length=64)
    verification_checks: list[dict[str, Any]] | None = Field(default=None, max_length=64)
    rollback_strategy: dict[str, Any] | None = None
    labels: dict[str, str] | None = None
    status: Literal["configured", "disabled"] | None = None


class AgentTaskCreate(StrictModel):
    changeset_id: str = Field(min_length=1, max_length=160)
    capability: str = Field(min_length=1, max_length=160)
    ttl_seconds: int = Field(default=300, ge=30, le=3600)


class AgentTaskClaim(StrictModel):
    nonce: str = Field(min_length=16, max_length=256)


class AgentTaskResult(StrictModel):
    status: Literal["SUCCEEDED", "FAILED"]
    summary: str = Field(min_length=1, max_length=2000)
    evidence: dict[str, Any] = Field(default_factory=dict)

class ServerCreate(StrictModel):
    hostname: str = Field(min_length=1, max_length=253)
    environment_id: str = Field(min_length=1, max_length=80)
    management_ip: str = Field(min_length=2, max_length=64)
    provisioning_ip: str | None = Field(default=None, min_length=2, max_length=64)
    bmc_ip: str | None = Field(default=None, min_length=2, max_length=64)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_user: str = Field(default="root", min_length=1, max_length=64)
    host_fingerprint: str = Field(min_length=20, max_length=256)
    connection_mode: ConnectionMode = "agent"
    credential_ref: str = Field(min_length=1, max_length=120)
    bmc_credential_ref: str | None = Field(default=None, max_length=120)
    architecture: str | None = Field(default=None, max_length=64)
    site: str | None = Field(default=None, max_length=120)
    rack: str | None = Field(default=None, max_length=120)
    zone: str | None = Field(default=None, max_length=120)
    labels: dict[str, str] = Field(default_factory=dict)


class ServerUpdate(StrictModel):
    hostname: str | None = Field(default=None, min_length=1, max_length=253)
    environment_id: str | None = Field(default=None, min_length=1, max_length=80)
    management_ip: str | None = Field(default=None, min_length=2, max_length=64)
    provisioning_ip: str | None = Field(default=None, min_length=2, max_length=64)
    bmc_ip: str | None = Field(default=None, min_length=2, max_length=64)
    ssh_port: int | None = Field(default=None, ge=1, le=65535)
    ssh_user: str | None = Field(default=None, min_length=1, max_length=64)
    host_fingerprint: str | None = Field(default=None, min_length=20, max_length=256)
    connection_mode: ConnectionMode | None = None
    credential_ref: str | None = Field(default=None, min_length=1, max_length=120)
    bmc_credential_ref: str | None = Field(default=None, max_length=120)
    architecture: str | None = Field(default=None, max_length=64)
    site: str | None = Field(default=None, max_length=120)
    rack: str | None = Field(default=None, max_length=120)
    zone: str | None = Field(default=None, max_length=120)
    labels: dict[str, str] | None = None
    status: Literal["configured", "disabled"] | None = None


class ServerPreflightResult(StrictModel):
    provider_job_id: str = Field(min_length=1, max_length=120)
    status: Literal["PASS", "WARN", "FAIL"]
    summary: str = Field(min_length=1, max_length=2000)
    checks: list[dict[str, Any]] = Field(default_factory=list, max_length=64)
    facts: dict[str, Any] = Field(default_factory=dict)


class BootstrapPlanCreate(StrictModel):
    provider: Literal["kubespray", "k3s", "rke2"]
    requested_by: str = Field(min_length=1, max_length=160)
    source_channel: Literal["telegram", "hermes-bot", "api"] = "api"
    cluster_name: str = Field(min_length=1, max_length=120)
    kubernetes_version: str = Field(min_length=1, max_length=80)
    node_role: Literal["control-plane", "worker", "control-plane-worker"] = "control-plane-worker"
    network_plugin: Literal["cilium"] = "cilium"
    hubble_enabled: bool = True
    radar_enabled: bool = True
    parameters: dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: int = Field(default=1800, ge=60, le=86400)


class ProviderJobTransition(StrictModel):
    state: Literal["RUNNING", "PAUSED", "SUCCEEDED", "FAILED"]
    stage: str = Field(min_length=1, max_length=80)
    message: str = Field(min_length=1, max_length=2000)
    evidence: dict[str, Any] = Field(default_factory=dict)


class ProviderJobRetry(StrictModel):
    reason: str = Field(min_length=1, max_length=1000)


class ClusterBlueprintCreate(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=1000)
    provider: Literal["kubespray", "k3s", "rke2"] = "kubespray"
    provider_version: str = Field(min_length=1, max_length=80)
    kubernetes_version: str = Field(min_length=1, max_length=80)
    network_plugin: Literal["cilium"] = "cilium"
    hubble_enabled: bool = True
    radar_enabled: bool = True
    topology: dict[str, Any] = Field(default_factory=dict)
    addon_defaults: list[str] = Field(default_factory=list, max_length=32)
    addon_versions: dict[str, str] = Field(default_factory=dict)
    labels: dict[str, str] = Field(default_factory=dict)


class OperationalProfileBlueprintCreate(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=1000)
    operational_profile: Literal["lab-minimal", "lab-full", "production", "production-ha", "production-hardened"]
    kubernetes_version: str = Field(min_length=1, max_length=80)
    provider_version: str = Field(min_length=1, max_length=80)
    addon_versions: dict[str, str] = Field(default_factory=dict)
    labels: dict[str, str] = Field(default_factory=dict)


class ClusterProfileCreate(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    environment_id: str = Field(min_length=1, max_length=80)
    blueprint_id: str = Field(min_length=1, max_length=120)
    server_ids: list[str] = Field(min_length=1, max_length=256)
    overrides: dict[str, Any] = Field(default_factory=dict)
    labels: dict[str, str] = Field(default_factory=dict)


class ClusterCreate(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    environment_id: str = Field(min_length=1, max_length=80)
    profile_id: str = Field(min_length=1, max_length=120)
    labels: dict[str, str] = Field(default_factory=dict)


class NodeRoleCreate(StrictModel):
    profile_id: str = Field(min_length=1, max_length=120)
    role: Literal["control-plane", "worker", "control-plane-worker"]
    server_ids: list[str] = Field(min_length=1, max_length=256)
    configuration: dict[str, Any] = Field(default_factory=dict)


class ProvisioningRunCreate(StrictModel):
    requested_by: str = Field(min_length=1, max_length=160)
    source_channel: Literal["telegram", "hermes-bot", "api"] = "api"
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)


class AddonPlanCreate(StrictModel):
    requested_by: str = Field(min_length=1, max_length=160)
    source_channel: Literal["telegram", "hermes-bot", "api"] = "api"
    addons: list[str] = Field(min_length=1, max_length=32)
    versions: dict[str, str] = Field(default_factory=dict)
    configuration: dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: int = Field(default=1800, ge=60, le=86400)


class UpgradePlanCreate(StrictModel):
    requested_by: str = Field(min_length=1, max_length=160)
    source_channel: Literal["telegram", "hermes-bot", "api"] = "api"
    target_version: str = Field(min_length=1, max_length=80)
    strategy: dict[str, Any] = Field(default_factory=lambda: {"mode": "rolling", "max_unavailable": 1})
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)


class BackupPlanCreate(StrictModel):
    requested_by: str = Field(min_length=1, max_length=160)
    source_channel: Literal["telegram", "hermes-bot", "api"] = "api"
    provider: Literal["velero"] = "velero"
    schedule: str = Field(min_length=1, max_length=120)
    retention_count: int = Field(default=14, ge=1, le=3650)
    scope: dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: int = Field(default=1800, ge=60, le=86400)


class RadarSnapshotCreate(StrictModel):
    observed_at: int
    health_score: int = Field(ge=0, le=100)
    resource_counts: dict[str, int] = Field(default_factory=dict)
    degraded_workloads: list[str] = Field(default_factory=list, max_length=256)
    warning_event_counts: dict[str, int] = Field(default_factory=dict)
    addon_health: dict[str, str] = Field(default_factory=dict)


class HubbleFlowSummaryCreate(StrictModel):
    window_start: int
    window_end: int
    verdict_counts: dict[str, int] = Field(default_factory=dict)
    workload_pairs: list[dict[str, Any]] = Field(default_factory=list, max_length=256)
    namespace_pairs: list[dict[str, Any]] = Field(default_factory=list, max_length=256)
    service_pairs: list[dict[str, Any]] = Field(default_factory=list, max_length=256)
    protocol_counts: dict[str, int] = Field(default_factory=dict)
    port_counts: dict[str, int] = Field(default_factory=dict)
    http_method_counts: dict[str, int] = Field(default_factory=dict)
    http_status_class_counts: dict[str, int] = Field(default_factory=dict)
    rps: float = Field(default=0.0, ge=0)
    byte_count: int = Field(default=0, ge=0)
    latency_ms: dict[str, float] = Field(default_factory=dict)
    tcp_state_counts: dict[str, int] = Field(default_factory=dict)
    policy_drop_counts: dict[str, int] = Field(default_factory=dict)
