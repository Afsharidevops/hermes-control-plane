from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from hermes_node_agent import capacity_runtime as runtime
from hermes_node_agent.main import app


def _snapshot() -> dict:
    snapshot = {
        "id": "ipr_proxmox001",
        "name": "pve-a",
        "kind": "proxmox",
        "endpoint": "https://pve.example.test:8006/api2/json",
        "credential_ref": "cred_capacity001",
        "credential_snapshot": {"id": "cred_capacity001", "status": "configured"},
        "api_version": "pve-8.2",
        "implementation_version": "pve-capacity-v1",
        "site": "dc1",
        "zone": "rack-a",
        "capabilities": {"node_allowlist": ["node-a"]},
        "labels": {},
        "health_status": "HEALTHY",
        "status": "configured",
    }
    return {**snapshot, "snapshot_hash": runtime.sha256_hex(snapshot)}


def _credential_root(tmp_path: Path, monkeypatch) -> None:
    directory = tmp_path / "cred_capacity001"
    directory.mkdir()
    (directory / "token-id").write_text("hermes@pam!capacity")
    (directory / "token-secret").write_text("test-token")
    (directory / "profile.json").write_text(json.dumps({
        "version": 1,
        "type": "proxmox-api-token",
        "token_id_file": "token-id",
        "token_secret_file": "token-secret",
    }))
    monkeypatch.setattr(runtime, "CREDENTIAL_ROOT", tmp_path)
    monkeypatch.setattr(runtime, "COLLECTION_ENABLED", True)


def _payload() -> dict:
    return {"data": [{"node": "node-a", "maxcpu": 16, "cpu": 0.25, "maxmem": 34359738368, "mem": 8589934592}]}


def test_proxmox_collects_live_sanitized_capacity(tmp_path: Path, monkeypatch):
    _credential_root(tmp_path, monkeypatch)
    seen = []

    def fake_request(url, *, authorization, ca_file, requests):
        seen.append((url, authorization, requests[0]))
        requests[0] += 1
        return _payload()

    monkeypatch.setattr(runtime, "_request", fake_request)
    result = runtime.collect(_snapshot())

    assert result["observation_state"] == "LIVE"
    assert result["capacity_kind"] == "host_utilization"
    assert result["resources"] == [
        {"scope_id": "node-a", "resource": "cpu", "unit": "cores", "limit": 16.0, "used": 4.0, "reserved": None, "headroom": 12.0, "semantics": "host_utilization"},
        {"scope_id": "node-a", "resource": "memory", "unit": "bytes", "limit": 34359738368.0, "used": 8589934592.0, "reserved": None, "headroom": 25769803776.0, "semantics": "host_utilization"},
    ]
    assert result["source"] == {"adapter": "proxmox-api-token-v1", "endpoint_profile": "pve-8.2", "request_count": 1}
    assert result["observation_hash"] == runtime.sha256_hex({key: value for key, value in result.items() if key != "observation_hash"})
    assert seen[0][0] == "https://pve.example.test:8006/api2/json/cluster/resources?type=node"
    assert seen[0][1] == "PVEAPIToken=hermes@pam!capacity=test-token"
    assert "test-token" not in json.dumps(result)


def test_collect_fails_closed_when_disabled(tmp_path: Path, monkeypatch):
    _credential_root(tmp_path, monkeypatch)
    monkeypatch.setattr(runtime, "COLLECTION_ENABLED", False)
    with pytest.raises(HTTPException, match="POLICY_DENIED"):
        runtime.collect(_snapshot())


def test_proxmox_rejects_missing_allowlisted_live_node(tmp_path: Path, monkeypatch):
    _credential_root(tmp_path, monkeypatch)
    monkeypatch.setattr(runtime, "_request", lambda *args, **kwargs: {"data": []})
    with pytest.raises(HTTPException, match="UPSTREAM_SCHEMA_INVALID"):
        runtime.collect(_snapshot())


def test_collect_rejects_tampered_provider_snapshot(tmp_path: Path, monkeypatch):
    _credential_root(tmp_path, monkeypatch)
    snapshot = _snapshot()
    snapshot["endpoint"] = "https://other.example.test:8006/api2/json"
    with pytest.raises(HTTPException, match="POLICY_DENIED"):
        runtime.collect(snapshot)


def test_collect_rejects_workstation_without_reading_credentials(tmp_path: Path, monkeypatch):
    _credential_root(tmp_path, monkeypatch)
    snapshot = _snapshot()
    snapshot["kind"] = "vmware-workstation"
    snapshot["snapshot_hash"] = runtime.sha256_hex({key: value for key, value in snapshot.items() if key != "snapshot_hash"})
    with pytest.raises(HTTPException, match="POLICY_DENIED"):
        runtime.collect(snapshot)


def test_profile_rejects_symlinked_secret(tmp_path: Path, monkeypatch):
    _credential_root(tmp_path, monkeypatch)
    directory = tmp_path / "cred_capacity001"
    (directory / "token-secret").unlink()
    (directory / "token-secret").symlink_to(tmp_path / "outside")
    with pytest.raises(HTTPException, match="POLICY_DENIED"):
        runtime.collect(_snapshot())


def test_capacity_route_requires_worker_token(monkeypatch):
    monkeypatch.setattr("hermes_node_agent.infrastructure_runtime.TOKEN", "worker-token")
    client = TestClient(app)
    assert client.post("/v1/capacity/refresh", json={"provider_snapshot": {}}).status_code == 401


def test_request_rejects_non_json_and_never_uses_proxy(monkeypatch):
    class Response:
        headers = {"Content-Type": "text/plain"}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, amount):
            return b"not-json"

    seen = []

    class Opener:
        def open(self, request, timeout):
            return Response()

    def fake_build_opener(*handlers):
        seen.extend(handlers)
        return Opener()

    monkeypatch.setattr(runtime.urllib.request, "build_opener", fake_build_opener)
    with pytest.raises(HTTPException, match="UPSTREAM_SCHEMA_INVALID"):
        runtime._request("https://provider.example.test/api", authorization="hidden", ca_file=None, requests=[0])
    assert any(isinstance(handler, runtime.urllib.request.ProxyHandler) for handler in seen)
    assert any(isinstance(handler, runtime._NoRedirect) for handler in seen)
