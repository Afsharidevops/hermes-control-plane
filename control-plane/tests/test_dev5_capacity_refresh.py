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
            "id": "cred_capacity001", "name": "proxmox-capacity", "kind": "generic",
            "provider": "credential-service", "status": "configured",
            "metadata": {"scope": "infrastructure-provider-worker"},
        },
    )
    assert credential.status_code == 200, credential.text
    response = client.post(
        "/v1/infrastructure-providers",
        headers=ADMIN,
        json={
            "name": "pve-a", "kind": "proxmox", "endpoint": "https://pve.example.test:8006/api2/json",
            "credential_ref": credential.json()["id"], "api_version": "pve-8.2", "implementation_version": "pve-capacity-v1",
            "site": "dc1", "zone": "rack-a", "capabilities": {"node_allowlist": ["node-a"]},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _live_result(snapshot: dict) -> dict:
    result = {
        "schema_version": 1,
        "operation": "capacity.refresh",
        "observation_state": "LIVE",
        "provider": {
            "id": snapshot["id"], "kind": "proxmox", "api_version": "pve-8.2",
            "implementation_version": "pve-capacity-v1", "snapshot_hash": snapshot["snapshot_hash"],
        },
        "observed_at": __import__("time").time_ns() // 1_000_000_000,
        "capacity_kind": "host_utilization",
        "coverage": "allowlisted_nodes",
        "scope": {"node_count": 1},
        "resources": [
            {"scope_id": "node-a", "resource": "cpu", "unit": "cores", "limit": 16.0, "used": 4.0, "reserved": None, "headroom": 12.0, "semantics": "host_utilization"},
            {"scope_id": "node-a", "resource": "memory", "unit": "bytes", "limit": 34359738368.0, "used": 8589934592.0, "reserved": None, "headroom": 25769803776.0, "semantics": "host_utilization"},
        ],
        "source": {"adapter": "proxmox-api-token-v1", "endpoint_profile": "pve-8.2", "request_count": 1},
        "credential_material_returned": False,
        "mutation_commands_executed": False,
        "arbitrary_cli": False,
        "arbitrary_shell": False,
    }
    return {**result, "observation_hash": sha256_hex(result)}


def _read_request(provider_id: str) -> dict:
    return {
        "requested_by": "admin:capacity", "source_channel": "api", "domain": "read",
        "operation": "capacity.refresh", "provider_id": provider_id,
    }


def test_capacity_refresh_returns_bound_live_observation_without_mutation_artifacts(client: TestClient, monkeypatch):
    provider = _proxmox_provider(client)
    seen: list[dict] = []

    async def fake_capacity_refresh(snapshot: dict) -> dict:
        seen.append(snapshot)
        return _live_result(snapshot)

    monkeypatch.setattr(provider_worker, "capacity_refresh", fake_capacity_refresh)
    response = client.post("/v1/operations-center/intents/plan", headers=ADMIN, json=_read_request(provider["id"]))
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["mode"] == "read"
    assert body["changeset"] is None and body["operation_job"] is None
    assert body["query_plan"]["mutation_runtime"] == "CONTRACT_ONLY"
    assert body["observation"]["provider"]["snapshot_hash"] == seen[0]["snapshot_hash"]
    assert client.get("/v1/operation-plans", headers=ADMIN).json() == []
    assert client.get("/v1/operation-jobs", headers=ADMIN).json() == []


def test_capacity_refresh_rejects_secret_shaped_worker_result(client: TestClient, monkeypatch):
    provider = _proxmox_provider(client)

    async def fake_capacity_refresh(snapshot: dict) -> dict:
        result = _live_result(snapshot)
        result["scope"] = {"node_count": 1, "token": "not-allowed"}
        result["observation_hash"] = sha256_hex({key: value for key, value in result.items() if key != "observation_hash"})
        return result

    monkeypatch.setattr(provider_worker, "capacity_refresh", fake_capacity_refresh)
    response = client.post("/v1/operations-center/intents/plan", headers=ADMIN, json=_read_request(provider["id"]))
    assert response.status_code == 502
    assert "secret" not in response.text


def test_capacity_refresh_rejects_unsupported_provider_before_worker(client: TestClient, monkeypatch):
    credential = client.post(
        "/v1/internal/credential-refs/sync", headers=CREDENTIAL_SERVICE,
        json={"id": "cred_awsprovider123", "name": "aws-worker", "kind": "generic", "provider": "credential-service", "status": "configured", "metadata": {}},
    )
    assert credential.status_code == 200
    provider = client.post(
        "/v1/infrastructure-providers", headers=ADMIN,
        json={"name": "aws-dev", "kind": "aws", "endpoint": "https://servicequotas.us-east-1.amazonaws.com", "credential_ref": credential.json()["id"], "api_version": "servicequotas-2019-06-24", "implementation_version": "aws-sigv4-quota-v1", "capabilities": {"region": "us-east-1"}},
    )
    assert provider.status_code == 201

    async def fail_if_called(snapshot: dict) -> dict:
        raise AssertionError("unsupported provider must not reach worker")

    monkeypatch.setattr(provider_worker, "capacity_refresh", fail_if_called)
    response = client.post("/v1/operations-center/intents/plan", headers=ADMIN, json=_read_request(provider.json()["id"]))
    assert response.status_code == 422
    assert "supported live capacity collector" in response.text


def test_capacity_collector_registration_cannot_authorize_proxmox_vm_mutation(client: TestClient):
    provider = _proxmox_provider(client)
    planned = client.post(
        "/v1/operations-center/intents/plan",
        headers={"Authorization": "Bearer test-bot"},
        json={
            "requested_by": "hermes-bot:capacity", "source_channel": "hermes-bot", "domain": "cloud",
            "operation": "vm.power", "provider_id": provider["id"],
            "desired_state": {"vm_id": 100, "node": "node-a", "target_state": "stopped"},
        },
    )
    assert planned.status_code == 422
    assert "versions do not match" in planned.text
