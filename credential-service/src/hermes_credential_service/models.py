from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

CredentialKind = Literal["kubeconfig", "ssh-key", "ssh-password", "token", "registry", "generic"]
CredentialBackend = Literal[
    "local-encrypted",
    "kubernetes-secret",
    "external-secrets",
    "vault",
    "aws-secrets-manager",
    "azure-key-vault",
    "gcp-secret-manager",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CredentialCreate(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    kind: CredentialKind
    backend: CredentialBackend = "local-encrypted"
    secret_material: SecretStr | None = None
    external_ref: str | None = Field(default=None, min_length=1, max_length=1000)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_backend_material(self):
        if self.backend == "local-encrypted":
            if self.secret_material is None or not self.secret_material.get_secret_value():
                raise ValueError("local-encrypted backend requires secret_material")
            if self.external_ref is not None:
                raise ValueError("local-encrypted backend does not accept external_ref")
        else:
            if self.secret_material is not None:
                raise ValueError("external reference backends must not receive secret_material")
            if not self.external_ref:
                raise ValueError("external reference backend requires external_ref")
        return self


class CredentialUpdate(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    metadata: dict[str, Any] | None = None
    actor: str = Field(default="credential-admin", min_length=1, max_length=160)

    @model_validator(mode="after")
    def validate_update(self):
        if self.name is None and self.metadata is None:
            raise ValueError("credential update requires name or metadata")
        return self


class CredentialRotate(StrictModel):
    secret_material: SecretStr | None = None
    external_ref: str | None = Field(default=None, min_length=1, max_length=1000)
    metadata: dict[str, Any] | None = None


class CredentialTest(StrictModel):
    actor: str = Field(default="credential-admin", min_length=1, max_length=160)


class CredentialSyncRetry(StrictModel):
    actor: str = Field(default="credential-admin", min_length=1, max_length=160)

class CredentialRevoke(StrictModel):
    actor: str = Field(default="credential-admin", min_length=1, max_length=160)
    reason: str = Field(min_length=1, max_length=1000)
