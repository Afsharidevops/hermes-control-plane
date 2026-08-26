from __future__ import annotations

import hashlib
import json
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

from hermes_control_plane import db  # noqa: E402
from hermes_control_plane import provider_worker  # noqa: E402
from hermes_control_plane.main import app  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin"}
BOT = {"Authorization": "Bearer test-bot"}
APPROVAL = {"Authorization": "Bearer test-approval"}
CREDENTIAL_SERVICE = {"Authorization": "Bearer test-credential-service"}


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(app) as c:
        yield c


def _host_network_provider(client: TestClient) -> dict:
    cred = client.post(
        "/v1/internal/credential-refs/sync", headers=CREDENTIAL_SERVICE,
        json={
            "id": "cred_hostnet00000001", "name": "host-network-worker", "kind": "generic",
            "provider": "credential-service", "status": "configured",
            "metadata": {"scope": "infrastructure-provider-worker"},
        },
    )
    assert cred.status_code == 200, cred.text
    response = client.post(
        "/v1/infrastructure-providers", headers=ADMIN,
        json={
            "name": "node-agent-01",
            "kind": "host-network",
            "endpoint": "agent://node-agent-01",
            "credential_ref": cred.json()["id"],
            "api_version": "linux-netlink-1",
            "implementation_version": "pyroute2-pinned-v1",
            "site": "dc1",
            "zone": "rack-a",
            "capabilities": {"interface_allowlist": ["eth0", "eth1", "bond0"]},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _host_network_preview(desired: dict, operation: str, plan_hash: str) -> dict:
    current = {
        "interfaces": [
            {"name": "eth0", "mac": "aa:bb:cc:dd:ee:01", "state": "down", "mtu": 1500},
        ],
        "bonds": [], "vlans": [], "addresses": [],
    }
    current_hash = hashlib.sha256(json.dumps(current, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return {
        "kind": "InfrastructureRuntimePreview",
        "provider_kind": "host-network",
        "operation": operation,
        "typed_plan_hash": plan_hash,
        "current": current,
        "current_hash": current_hash,
        "desired_state": desired,
        "diff": [{"field": "host.interface.state", "from": "down", "to": "up"}],
        "active_probe": True,
        "credential_material_returned": False,
        "secret_output_suppressed": True,
        "arbitrary_cli": False,
        "arbitrary_shell": False,
    }


def test_host_network_is_registered_as_a_valid_provider_kind(client: TestClient):
    provider = _host_network_provider(client)
    assert provider["kind"] == "host-network"


def test_host_network_plan_uses_trusted_runtime_and_binds_worker_preview(client: TestClient, monkeypatch):
    provider = _host_network_provider(client)
    seen = []

    async def fake_post(path, payload):
        seen.append(path)
        preliminary = payload["changeset_plan"]["parameters"]["typed_plan"]
        return _host_network_preview(preliminary["desired_state"], preliminary["operation"], preliminary["plan_hash"])

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:c8", "source_channel": "hermes-bot", "domain": "bare-metal",
            "operation": "interface.configure", "provider_id": provider["id"],
            "desired_state": {"interface": "eth0", "state": "up", "mtu": 1500},
        },
    )
    assert planned.status_code == 201, planned.text
    body = planned.json()
    assert seen[0] == "/v1/infrastructure/preview"
    assert body["operation_job"]["executor"] == "infrastructure-provider-worker"
    plan = body["operation_plan"]["plan"]
    assert plan["runtime"]["state"] == "RUNTIME_CAPABLE"
    assert plan["credential_material_in_plan"] is False
    assert plan["arbitrary_cli_or_shell"] is False


def test_host_network_rejects_unsupported_desired_state_before_worker_call(client: TestClient, monkeypatch):
    provider = _host_network_provider(client)
    called = []

    async def fake_post(path, payload):
        called.append(path)
        raise AssertionError("worker should not be called")

    monkeypatch.setattr(provider_worker, "post", fake_post)
    denied = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:c8", "source_channel": "hermes-bot", "domain": "bare-metal",
            "operation": "interface.configure", "provider_id": provider["id"],
            "desired_state": {"interface": "eth0", "state": "up", "command": "rm -rf /"},
        },
    )
    assert denied.status_code == 422
    assert called == []


def test_host_network_execute_routes_signed_ticket_and_records_active_verification(client: TestClient, monkeypatch):
    provider = _host_network_provider(client)

    async def fake_post(path, payload):
        if path == "/v1/infrastructure/preview":
            preliminary = payload["changeset_plan"]["parameters"]["typed_plan"]
            return _host_network_preview(preliminary["desired_state"], preliminary["operation"], preliminary["plan_hash"])
        assert path == "/v1/infrastructure/execute"
        return {
            "state": "SUCCEEDED",
            "provider_kind": "host-network",
            "operation": payload["ticket"]["plan"]["parameters"]["typed_plan"]["operation"],
            "typed_plan_hash": payload["ticket"]["preconditions"]["typed_plan_hash"],
            "verification": {
                "checks": [
                    {"id": "provider-state-drift", "status": "PASS", "summary": "Exact approved preview matched", "evidence": {"provider_id": provider["id"]}},
                    {"id": "host-network-active-verify", "status": "PASS", "summary": "Interface state converged", "evidence": {"interface": "eth0", "state": "up"}},
                ],
                "evidence": {"provider_kind": "host-network", "arbitrary_cli": False, "raw_credentials_returned": False},
                "observed_at": 1787330000,
            },
        }

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:c8", "source_channel": "hermes-bot", "domain": "bare-metal",
            "operation": "interface.configure", "provider_id": provider["id"],
            "desired_state": {"interface": "eth0", "state": "up", "mtu": 1500},
        },
    ).json()
    assert client.post(f"/v1/changesets/{planned['changeset']['id']}/request-approval", headers=BOT).status_code == 200
    approved = client.post(
        f"/v1/changesets/{planned['changeset']['id']}/approve", headers=APPROVAL,
        json={"approver": "approval-bot:c8", "plan_hash": planned["changeset"]["plan_hash"]},
    )
    assert approved.status_code == 201, approved.text
    auth = client.post(f"/v1/operation-jobs/{planned['operation_job']['id']}/authorize", headers=BOT)
    assert auth.status_code == 200, auth.text
    executed = client.post(
        f"/v1/operation-jobs/{planned['operation_job']['id']}/execute", headers=BOT,
        json={"execution_ticket": auth.json()["execution_ticket"], "signature": auth.json()["signature"], "actor": "hermes-bot:c8"},
    )
    assert executed.status_code == 200, executed.text
    assert executed.json()["operation_job"]["state"] == "SUCCEEDED"
    assert executed.json()["verification"]["status"] == "PASS"
    assert executed.json()["infrastructure_worker_result"]["verification"]["checks"][1]["id"] == "host-network-active-verify"
