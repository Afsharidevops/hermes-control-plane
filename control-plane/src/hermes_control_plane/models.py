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
    policy_generation: int = Field(default=1, ge=1)
    ttl_seconds: int = Field(default=900, ge=60, le=86400)


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
