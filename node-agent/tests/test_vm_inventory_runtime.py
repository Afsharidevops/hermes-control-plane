from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from hermes_node_agent import vm_inventory_runtime as runtime
from hermes_node_agent.main import app


def _snapshot() -> dict:
    snapshot = {
        "id": "ipr_proxmox001",
        "name": "pve-a",
        "kind": "proxmox",
        "endpoint": "https://pve.example.test:8006/api2/json",
        "credential_ref": "cred_inventory001",
        "credential_snapshot": {"id": "cred_inventory001", "status": "configured"},
        "api_version": "pve-8.2",
        "implementation_version": "pve-vm-inventory-v1",
        "site": "dc1",
        "zone": "rack-a",
        "capabilities": {"node_allowlist": ["node-a", "node-b"]},
        "labels": {},
        "health_status": "HEALTHY",
        "status": "configured",
    }
    return {**snapshot, "snapshot_hash": runtime.sha256_hex(snapshot)}


def _credential_root(tmp_path: Path, monkeypatch) -> None:
    directory = tmp_path / "cred_inventory001"
    directory.mkdir()
    (directory / "token-id").write_text("hermes@pam!inventory")
    (directory / "token-secret").write_text("test-token")
    (directory / "profile.json").write_text(json.dumps({
        "version": 1,
        "type": "proxmox-api-token",
        "token_id_file": "token-id",
        "token_secret_file": "token-secret",
    }))
    monkeypatch.setattr(runtime, "CREDENTIAL_ROOT", tmp_path)
    monkeypatch.setattr(runtime, "COLLECTION_ENABLED", True)


def _node_payload() -> dict:
    return {"data": [{"node": "node-a"}, {"node": "node-b"}]}


def _vm_payload() -> dict:
    return {"data": [
        {"vmid": 200, "node": "node-b", "type": "lxc", "status": "stopped", "template": 0, "name": "hidden"},
        {"vmid": 100, "node": "node-a", "type": "qemu", "status": "running", "template": False, "ip": "192.0.2.1"},
        {"vmid": 999, "node": "outside", "type": "qemu", "status": "running", "template": False},
    ]}


def test_collects_two_live_reads_and_returns_sanitized_sorted_inventory(tmp_path: Path, monkeypatch):
    _credential_root(tmp_path, monkeypatch)
    seen = []

    def fake_request(url, *, authorization, ca_file, requests):
        seen.append((url, authorization, requests[0]))
        requests[0] += 1
        return _node_payload() if "type=node" in url else _vm_payload()

    monkeypatch.setattr(runtime, "_request", fake_request)
    result = runtime.collect(_snapshot())

    assert result["observation_state"] == "LIVE"
    assert result["inventory_kind"] == "virtual_machine_identity_state"
    assert result["coverage"] == "allowlisted_nodes"
    assert result["scope"] == {"node_count": 2, "vm_count": 2}
    assert result["records"] == [
        {"vm_id": 100, "node": "node-a", "type": "qemu", "power_state": "running", "template": False},
        {"vm_id": 200, "node": "node-b", "type": "lxc", "power_state": "stopped", "template": False},
    ]
    assert result["source"] == {"adapter": "proxmox-api-token-v1", "endpoint_profile": "pve-8.2", "request_count": 2}
    assert result["observation_hash"] == runtime.sha256_hex({key: value for key, value in result.items() if key != "observation_hash"})
    assert [entry[0] for entry in seen] == [
        "https://pve.example.test:8006/api2/json/cluster/resources?type=node",
        "https://pve.example.test:8006/api2/json/cluster/resources?type=vm",
    ]
    assert all(entry[1] == "PVEAPIToken=hermes@pam!inventory=test-token" for entry in seen)
    assert "test-token" not in json.dumps(result)
    assert "hidden" not in json.dumps(result)


def test_collect_fails_closed_when_disabled(tmp_path: Path, monkeypatch):
    _credential_root(tmp_path, monkeypatch)
    monkeypatch.setattr(runtime, "COLLECTION_ENABLED", False)
    with pytest.raises(HTTPException, match="POLICY_DENIED"):
        runtime.collect(_snapshot())


def test_collect_requires_allowlisted_node_coverage_before_vm_read(tmp_path: Path, monkeypatch):
    _credential_root(tmp_path, monkeypatch)
    seen = []

    def fake_request(*args, **kwargs):
        seen.append(args)
        return {"data": [{"node": "node-a"}]}

    monkeypatch.setattr(runtime, "_request", fake_request)
    with pytest.raises(HTTPException, match="UPSTREAM_SCHEMA_INVALID"):
        runtime.collect(_snapshot())
    assert len(seen) == 1


def test_collect_rejects_tampered_snapshot_before_credential_access(tmp_path: Path, monkeypatch):
    _credential_root(tmp_path, monkeypatch)
    snapshot = _snapshot()
    snapshot["endpoint"] = "https://other.example.test:8006/api2/json"
    with pytest.raises(HTTPException, match="POLICY_DENIED"):
        runtime.collect(snapshot)


def test_collect_rejects_unknown_vm_shape_and_duplicate_ids(tmp_path: Path, monkeypatch):
    _credential_root(tmp_path, monkeypatch)

    def fake_request(url, **kwargs):
        return _node_payload() if "type=node" in url else {"data": [
            {"vmid": 100, "node": "node-a", "type": "qemu", "status": "running", "template": False},
            {"vmid": 100, "node": "node-b", "type": "qemu", "status": "running", "template": False},
        ]}

    monkeypatch.setattr(runtime, "_request", fake_request)
    with pytest.raises(HTTPException, match="UPSTREAM_SCHEMA_INVALID"):
        runtime.collect(_snapshot())


def test_collect_rejects_unsupported_provider_without_reading_credentials(tmp_path: Path, monkeypatch):
    _credential_root(tmp_path, monkeypatch)
    snapshot = _snapshot()
    snapshot["kind"] = "vmware-workstation"
    snapshot["snapshot_hash"] = runtime.sha256_hex({key: value for key, value in snapshot.items() if key != "snapshot_hash"})
    with pytest.raises(HTTPException, match="POLICY_DENIED"):
        runtime.collect(snapshot)


def test_inventory_route_requires_worker_token(monkeypatch):
    monkeypatch.setattr("hermes_node_agent.infrastructure_runtime.TOKEN", "worker-token")
    client = TestClient(app)
    assert client.post("/v1/vm/inventory/refresh", json={"provider_snapshot": {}}).status_code == 401


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
