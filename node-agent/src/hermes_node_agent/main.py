from __future__ import annotations

import os
import socket
from typing import Any

from fastapi import FastAPI, Header
from pydantic import BaseModel, ConfigDict, Field

from . import capacity_runtime
from . import infrastructure_runtime
from . import proxmox_runtime
from . import provider_runtime
from . import vm_inventory_runtime

VERSION = "0.5.11-dev.5"
app = FastAPI(title="Hermes Node Agent / Cluster Provider Worker", version=VERSION)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProviderPreviewRequest(StrictModel):
    changeset_plan: dict[str, Any]


class ProviderExecuteRequest(StrictModel):
    ticket: dict[str, Any]
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")


class CapacityRefreshRequest(StrictModel):
    provider_snapshot: dict[str, Any]


class VmInventoryRefreshRequest(StrictModel):
    provider_snapshot: dict[str, Any]


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "hermes-node-agent",
        "version": VERSION,
        "node": os.getenv("HERMES_AGENT_NAME", socket.gethostname()),
        "mode": "cluster-provider-worker",
        "execution_enabled": provider_runtime.EXECUTION_ENABLED,
        "infrastructure_execution_enabled": infrastructure_runtime.EXECUTION_ENABLED,
        "capabilities": ["kubespray", "k3s", "rke2", "cluster-day2", "direct-etcd", "offline-artifact-binding", "redfish-runtime", "redfish-virtual-media-runtime", "ipmi-lanplus-runtime", "pxe-unattended-runtime", "host-network-runtime", "openconfig-restconf-v1-vlan-port-lldp-runtime", "proxmox-capacity-collector-v1" if capacity_runtime.COLLECTION_ENABLED else "proxmox-capacity-collector-disabled", "proxmox-vm-inventory-collector-v1" if vm_inventory_runtime.COLLECTION_ENABLED else "proxmox-vm-inventory-collector-disabled", "proxmox-vm-runtime-v1" if infrastructure_runtime.EXECUTION_ENABLED and proxmox_runtime.RUNTIME_ENABLED else "proxmox-vm-runtime-disabled", "vmware-workstation-contract-only", "vmware-contract-only", "openstack-contract-only", "aws-contract-only", "azure-contract-only", "gcp-contract-only"],
        "arbitrary_shell": False,
        "arbitrary_ssh_command": False,
    }


@app.post("/v1/provider/preview")
def provider_preview(payload: ProviderPreviewRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    provider_runtime.require_token(authorization)
    return provider_runtime.preview(payload.changeset_plan)


@app.post("/v1/provider/execute")
def provider_execute(payload: ProviderExecuteRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    provider_runtime.require_token(authorization)
    return provider_runtime.execute(payload.ticket, payload.signature)


@app.post("/v1/capacity/refresh")
def capacity_refresh(payload: CapacityRefreshRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    infrastructure_runtime.require_token(authorization)
    return capacity_runtime.collect(payload.provider_snapshot)


@app.post("/v1/vm/inventory/refresh")
def vm_inventory_refresh(payload: VmInventoryRefreshRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    infrastructure_runtime.require_token(authorization)
    return vm_inventory_runtime.collect(payload.provider_snapshot)


@app.post("/v1/infrastructure/preview")
def infrastructure_preview(payload: ProviderPreviewRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    infrastructure_runtime.require_token(authorization)
    return infrastructure_runtime.preview(payload.changeset_plan)


@app.post("/v1/infrastructure/execute")
def infrastructure_execute(payload: ProviderExecuteRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    infrastructure_runtime.require_token(authorization)
    return infrastructure_runtime.execute(payload.ticket, payload.signature)
