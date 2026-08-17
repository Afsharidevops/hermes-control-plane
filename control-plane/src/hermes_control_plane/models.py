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
