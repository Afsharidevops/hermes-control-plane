from __future__ import annotations

import hmac
import os
import re
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict

from . import host_observation

VERSION = "0.5.11"
IDENTITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{2,119}$")
HOST_SYS_NET_ROOT = Path("/host-sys/class/net")
HOST_VLAN_CONFIG_PATH = Path("/host-proc/net/vlan/config")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HostNetworkCollectionRequest(StrictModel):
    pass


def _configured_identity() -> str:
    identity = os.getenv("HERMES_HOST_OBSERVER_IDENTITY", "")
    if not IDENTITY_RE.fullmatch(identity):
        raise HTTPException(status_code=503, detail="host observer identity is not configured")
    return identity


def _require_token(authorization: str | None) -> None:
    token = os.getenv("HERMES_HOST_OBSERVER_TOKEN", "")
    if not token:
        raise HTTPException(status_code=503, detail="host observer token is not configured")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing host observer bearer token")
    supplied = authorization.removeprefix("Bearer ").strip()
    if not hmac.compare_digest(supplied, token):
        raise HTTPException(status_code=401, detail="invalid host observer bearer token")


app = FastAPI(title="Hermes Host Observer", version=VERSION)


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "hermes-host-observer",
        "version": VERSION,
        "collector_kind": host_observation.COLLECTOR_KIND,
        "collector_identity_configured": bool(IDENTITY_RE.fullmatch(os.getenv("HERMES_HOST_OBSERVER_IDENTITY", ""))),
        "mutation_commands_executed": False,
        "credential_material_returned": False,
    }


@app.post("/v1/collectors/host-network")
def collect_host_network(payload: HostNetworkCollectionRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    del payload
    _require_token(authorization)
    return host_observation.collect_host_network(
        collector_identity=_configured_identity(),
        sys_net_root=HOST_SYS_NET_ROOT,
        vlan_config_path=HOST_VLAN_CONFIG_PATH,
    )
