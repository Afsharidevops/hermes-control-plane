from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ["HERMES_CONTROL_ADMIN_TOKEN"] = "test-admin"
os.environ["HERMES_BOT_SERVICE_TOKEN"] = "test-bot"
os.environ["HERMES_APPROVAL_BOT_TOKEN"] = "test-approval"
os.environ["HERMES_APPROVAL_HMAC_KEY"] = "approval-hmac-key-0123456789abcdef0123456789abcdef"
os.environ["HERMES_AGENT_TASK_HMAC_KEY"] = "agent-task-key-0123456789abcdef0123456789abcdef"
os.environ["HERMES_EXECUTION_HMAC_KEY"] = "execution-ticket-key-0123456789abcdef0123456789abcdef"
os.environ["HERMES_CREDENTIAL_SERVICE_TOKEN"] = "test-credential-service"

from hermes_control_plane import db, provider_worker  # noqa: E402
from hermes_control_plane.canonical import sha256_hex  # noqa: E402
from hermes_control_plane.main import app  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin"}
CREDENTIAL_SERVICE = {"Authorization": "Bearer test-credential-service"}


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(app) as c:
        yield c


def _proxmox_provider(client: TestClient) -> dict:
    credential = client.post(
        "/v1/internal/credential-refs/sync",
        headers=CREDENTIAL_SERVICE,
        json={
            "id": "cred_inventory001", "name": "proxmox-inventory", "kind": "generic",
            "provider": "credential-service", "status": "configured",
            "metadata": {"scope": "infrastructure-provider-worker"},
        },
    )
    assert credential.status_code == 200, credential.text
    response = client.post(
        "/v1/infrastructure-providers",
        headers=ADMIN,
        json={
            "name": "pve-b", "kind": "proxmox", "endpoint": "https://pve.example.test:8006/api2/json",
            "credential_ref": credential.json()["id"], "api_version": "pve-8.2", "implementation_version": "pve-vm-inventory-v1",
            "site": "dc1", "zone": "rack-a", "capabilities": {"node_allowlist": ["node-a", "node-b"]},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _live_result(snapshot: dict, *, records: list[dict] | None = None) -> dict:
    if records is None:
        records = [
            {"vm_id": 100, "node": "node-a", "type": "qemu", "power_state": "running", "template": False},
            {"vm_id": 200, "node": "node-b", "type": "lxc", "power_state": "stopped", "template": False},
        ]
    result = {
        "schema_version": 1,
        "operation": "vm.inventory.refresh",
        "observation_state": "LIVE",
        "provider": {
            "id": snapshot["id"], "kind": "proxmox", "api_version": "pve-8.2",
            "implementation_version": "pve-vm-inventory-v1", "snapshot_hash": snapshot["snapshot_hash"],
        },
        "observed_at": __import__("time").time_ns() // 1_000_000_000,
        "inventory_kind": "virtual_machine_identity_state",
        "coverage": "allowlisted_nodes",
        "scope": {"node_count": 2, "vm_count": len(records)},
        "records": records,
        "source": {"adapter": "proxmox-api-token-v1", "endpoint_profile": "pve-8.2", "request_count": 2},
        "credential_material_returned": False,
        "mutation_commands_executed": False,
        "arbitrary_cli": False,
        "arbitrary_shell": False,
    }
    return {**result, "observation_hash": sha256_hex(result)}


def _read_request(provider_id: str) -> dict:
    return {
        "requested_by": "admin:inventory", "source_channel": "api", "domain": "read",
        "operation": "vm.inventory.refresh", "provider_id": provider_id,
    }


def test_vm_inventory_refresh_returns_bound_live_observation_without_mutation_artifacts(client: TestClient, monkeypatch):
    provider = _proxmox_provider(client)
    seen: list[dict] = []

    async def fake_vm_inventory_refresh(snapshot: dict) -> dict:
        seen.append(snapshot)
        return _live_result(snapshot)

    monkeypatch.setattr(provider_worker, "vm_inventory_refresh", fake_vm_inventory_refresh)
    response = client.post("/v1/operations-center/intents/plan", headers=ADMIN, json=_read_request(provider["id"]))
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["mode"] == "read"
    assert body["changeset"] is None and body["operation_job"] is None
    assert body["query_plan"]["mutation_runtime"] == "CONTRACT_ONLY"
    assert body["observation"]["provider"]["snapshot_hash"] == seen[0]["snapshot_hash"]
    assert body["observation"]["records"] == [
        {"vm_id": 100, "node": "node-a", "type": "qemu", "power_state": "running", "template": False},
        {"vm_id": 200, "node": "node-b", "type": "lxc", "power_state": "stopped", "template": False},
    ]
    assert client.get("/v1/operation-plans", headers=ADMIN).json() == []
    assert client.get("/v1/operation-jobs", headers=ADMIN).json() == []


def test_vm_inventory_refresh_rejects_secret_shaped_worker_result(client: TestClient, monkeypatch):
    provider = _proxmox_provider(client)

    async def fake_vm_inventory_refresh(snapshot: dict) -> dict:
        result = _live_result(snapshot)
        result["source"] = {"adapter": "proxmox-api-token-v1", "endpoint_profile": "pve-8.2", "request_count": 2, "token": "not-allowed"}
        result["observation_hash"] = sha256_hex({key: value for key, value in result.items() if key != "observation_hash"})
        return result

    monkeypatch.setattr(provider_worker, "vm_inventory_refresh", fake_vm_inventory_refresh)
    response = client.post("/v1/operations-center/intents/plan", headers=ADMIN, json=_read_request(provider["id"]))
    assert response.status_code == 502
    assert "token" not in response.text


def test_vm_inventory_refresh_rejects_unsupported_provider_before_worker(client: TestClient, monkeypatch):
    credential = client.post(
        "/v1/internal/credential-refs/sync", headers=CREDENTIAL_SERVICE,
        json={"id": "cred_awsprovider456", "name": "aws-worker", "kind": "generic", "provider": "credential-service", "status": "configured", "metadata": {}},
    )
    assert credential.status_code == 200
    provider = client.post(
        "/v1/infrastructure-providers", headers=ADMIN,
        json={"name": "aws-dev2", "kind": "aws", "endpoint": "https://servicequotas.us-east-1.amazonaws.com", "credential_ref": credential.json()["id"], "api_version": "servicequotas-2019-06-24", "implementation_version": "aws-sigv4-quota-v1", "capabilities": {"region": "us-east-1"}},
    )
    assert provider.status_code == 201

    async def fail_if_called(snapshot: dict) -> dict:
        raise AssertionError("unsupported provider must not reach worker")

    monkeypatch.setattr(provider_worker, "vm_inventory_refresh", fail_if_called)
    response = client.post("/v1/operations-center/intents/plan", headers=ADMIN, json=_read_request(provider.json()["id"]))
    assert response.status_code == 422
    assert "supported live VM inventory collector" in response.text


def test_vm_inventory_refresh_rejects_malformed_record_keys(client: TestClient, monkeypatch):
    provider = _proxmox_provider(client)

    async def fake_vm_inventory_refresh(snapshot: dict) -> dict:
        result = _live_result(snapshot, records=[{"vm_id": 100, "node": "node-a", "type": "qemu", "power_state": "running", "template": False, "name": "hidden"}])
        result["observation_hash"] = sha256_hex({key: value for key, value in result.items() if key != "observation_hash"})
        return result

    monkeypatch.setattr(provider_worker, "vm_inventory_refresh", fake_vm_inventory_refresh)
    response = client.post("/v1/operations-center/intents/plan", headers=ADMIN, json=_read_request(provider["id"]))
    assert response.status_code == 502
    assert "hidden" not in response.text


def test_vm_inventory_refresh_rejects_duplicate_vm_ids(client: TestClient, monkeypatch):
    provider = _proxmox_provider(client)

    async def fake_vm_inventory_refresh(snapshot: dict) -> dict:
        result = _live_result(snapshot, records=[
            {"vm_id": 100, "node": "node-a", "type": "qemu", "power_state": "running", "template": False},
            {"vm_id": 100, "node": "node-b", "type": "lxc", "power_state": "stopped", "template": False},
        ])
        result["observation_hash"] = sha256_hex({key: value for key, value in result.items() if key != "observation_hash"})
        return result

    monkeypatch.setattr(provider_worker, "vm_inventory_refresh", fake_vm_inventory_refresh)
    response = client.post("/v1/operations-center/intents/plan", headers=ADMIN, json=_read_request(provider["id"]))
    assert response.status_code == 502
    assert "duplicate VM IDs" in response.text


def test_vm_inventory_refresh_rejects_mismatched_scope_count(client: TestClient, monkeypatch):
    provider = _proxmox_provider(client)

    async def fake_vm_inventory_refresh(snapshot: dict) -> dict:
        result = _live_result(snapshot)
        result["scope"] = {"node_count": 2, "vm_count": 5}
        result["observation_hash"] = sha256_hex({key: value for key, value in result.items() if key != "observation_hash"})
        return result

    monkeypatch.setattr(provider_worker, "vm_inventory_refresh", fake_vm_inventory_refresh)
    response = client.post("/v1/operations-center/intents/plan", headers=ADMIN, json=_read_request(provider["id"]))
    assert response.status_code == 502
    assert "records are invalid" in response.text


def test_vm_inventory_refresh_rejects_over_limit_inventory(client: TestClient, monkeypatch):
    provider = _proxmox_provider(client)

    async def fake_vm_inventory_refresh(snapshot: dict) -> dict:
        records = [{"vm_id": i, "node": "node-a", "type": "qemu", "power_state": "running", "template": False} for i in range(1, 514)]
        result = _live_result(snapshot, records=records)
        result["observation_hash"] = sha256_hex({key: value for key, value in result.items() if key != "observation_hash"})
        return result

    monkeypatch.setattr(provider_worker, "vm_inventory_refresh", fake_vm_inventory_refresh)
    response = client.post("/v1/operations-center/intents/plan", headers=ADMIN, json=_read_request(provider["id"]))
    assert response.status_code == 502


def test_vm_inventory_refresh_rejects_stale_observation(client: TestClient, monkeypatch):
    provider = _proxmox_provider(client)

    async def fake_vm_inventory_refresh(snapshot: dict) -> dict:
        result = _live_result(snapshot)
        result["observed_at"] = result["observed_at"] - 3600
        result["observation_hash"] = sha256_hex({key: value for key, value in result.items() if key != "observation_hash"})
        return result

    monkeypatch.setattr(provider_worker, "vm_inventory_refresh", fake_vm_inventory_refresh)
    response = client.post("/v1/operations-center/intents/plan", headers=ADMIN, json=_read_request(provider["id"]))
    assert response.status_code == 502
    assert "stale" in response.text


def test_vm_inventory_refresh_rejects_wrong_operation_label(client: TestClient, monkeypatch):
    provider = _proxmox_provider(client)

    async def fake_vm_inventory_refresh(snapshot: dict) -> dict:
        result = _live_result(snapshot)
        result["operation"] = "capacity.refresh"
        result["observation_hash"] = sha256_hex({key: value for key, value in result.items() if key != "observation_hash"})
        return result

    monkeypatch.setattr(provider_worker, "vm_inventory_refresh", fake_vm_inventory_refresh)
    response = client.post("/v1/operations-center/intents/plan", headers=ADMIN, json=_read_request(provider["id"]))
    assert response.status_code == 502


def test_vm_inventory_refresh_rejects_mismatched_provider_snapshot(client: TestClient, monkeypatch):
    provider = _proxmox_provider(client)

    async def fake_vm_inventory_refresh(snapshot: dict) -> dict:
        result = _live_result(snapshot)
        result["provider"] = {**result["provider"], "snapshot_hash": "0" * 64}
        result["observation_hash"] = sha256_hex({key: value for key, value in result.items() if key != "observation_hash"})
        return result

    monkeypatch.setattr(provider_worker, "vm_inventory_refresh", fake_vm_inventory_refresh)
    response = client.post("/v1/operations-center/intents/plan", headers=ADMIN, json=_read_request(provider["id"]))
    assert response.status_code == 502
    assert "does not match the provider snapshot" in response.text


def test_vm_inventory_refresh_rejects_altered_observation_hash(client: TestClient, monkeypatch):
    provider = _proxmox_provider(client)

    async def fake_vm_inventory_refresh(snapshot: dict) -> dict:
        result = _live_result(snapshot)
        result["observation_hash"] = "0" * 64
        return result

    monkeypatch.setattr(provider_worker, "vm_inventory_refresh", fake_vm_inventory_refresh)
    response = client.post("/v1/operations-center/intents/plan", headers=ADMIN, json=_read_request(provider["id"]))
    assert response.status_code == 502
    assert "observation hash is invalid" in response.text


def test_proxmox_vm_mutation_remains_contract_only(client: TestClient):
    provider = _proxmox_provider(client)
    planned = client.post(
        "/v1/operations-center/intents/plan",
        headers={"Authorization": "Bearer test-bot"},
        json={
            "requested_by": "hermes-bot:inventory", "source_channel": "hermes-bot", "domain": "cloud",
            "operation": "vm.power", "provider_id": provider["id"], "desired_state": {},
        },
    )
    assert planned.status_code == 201, planned.text
    assert planned.json()["operation_plan"]["plan"]["runtime"]["state"] == "CONTRACT_ONLY"
