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


def _switch_provider(client: TestClient) -> dict:
    cred = client.post(
        "/v1/internal/credential-refs/sync", headers=CREDENTIAL_SERVICE,
        json={
            "id": "cred_switch000000001", "name": "switch-worker", "kind": "generic",
            "provider": "credential-service", "status": "configured",
            "metadata": {"scope": "infrastructure-provider-worker"},
        },
    )
    assert cred.status_code == 200, cred.text
    response = client.post(
        "/v1/infrastructure-providers", headers=ADMIN,
        json={
            "name": "leaf-switch-01", "kind": "network-switch",
            "endpoint": "https://198.51.100.10/restconf/data",
            "credential_ref": cred.json()["id"],
            "api_version": "openconfig-restconf-1.0",
            "implementation_version": "openconfig-restconf-v1",
            "site": "dc1", "zone": "rack-a",
            "capabilities": {
                "profile": "openconfig-restconf-v1",
                "model": "ExampleSwitch-48P",
                "port_allowlist": ["Ethernet1", "Ethernet2"],
                "vlan_allowlist": [100, 200],
                "port_modes": {"Ethernet1": ["access"], "Ethernet2": ["trunk"]},
            },
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _current_for(operation: str, desired: dict) -> dict:
    if operation == "vlan.ensure":
        return {"vlan_id": desired["vlan_id"], "present": False, "name": "", "etag": ""}
    if operation == "port.configure":
        return {"port": desired["port"], "mode": "", "access_vlan": None, "trunk_vlans": [], "etag": "etag-1"}
    return {
        "ports": [
            {"port": "Ethernet1", "neighbors": [{"port": "Ethernet1", "system_name": "leaf-switch-02"}], "etag": "etag-1"},
            {"port": "Ethernet2", "neighbors": [], "etag": "etag-2"},
        ],
    }


def _switch_preview(preliminary: dict) -> dict:
    current = _current_for(preliminary["operation"], preliminary["desired_state"])
    current_hash = hashlib.sha256(
        json.dumps(current, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    return {
        "kind": "InfrastructureRuntimePreview",
        "provider_kind": "network-switch",
        "operation": preliminary["operation"],
        "typed_plan_hash": preliminary["plan_hash"],
        "current": current,
        "current_hash": current_hash,
        "desired_state": preliminary["desired_state"],
        "diff": [] if preliminary["operation"] == "lldp.observe" else [{"field": "switch.config", "from": "before", "to": "after"}],
        "active_probe": True,
        "credential_material_returned": False,
        "secret_output_suppressed": True,
        "arbitrary_cli": False,
        "arbitrary_shell": False,
    }


def _plan(client: TestClient, provider: dict, operation: str, desired_state: dict) -> dict:
    response = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:c9", "source_channel": "hermes-bot", "domain": "network",
            "operation": operation, "provider_id": provider["id"], "desired_state": desired_state,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _approve_and_authorize(client: TestClient, planned: dict) -> dict:
    changeset = planned["changeset"]
    assert client.post(f"/v1/changesets/{changeset['id']}/request-approval", headers=BOT).status_code == 200
    approved = client.post(
        f"/v1/changesets/{changeset['id']}/approve", headers=APPROVAL,
        json={"approver": "approval-bot:c9", "plan_hash": changeset["plan_hash"]},
    )
    assert approved.status_code == 201, approved.text
    authorized = client.post(f"/v1/operation-jobs/{planned['operation_job']['id']}/authorize", headers=BOT)
    assert authorized.status_code == 200, authorized.text
    return authorized.json()


def test_network_switch_registration_requires_pinned_profile_and_safe_endpoint(client: TestClient):
    provider = _switch_provider(client)
    assert provider["kind"] == "network-switch"
    assert provider["endpoint"] == "https://198.51.100.10/restconf/data"

    bad_endpoint = client.post(
        "/v1/infrastructure-providers", headers=ADMIN,
        json={
            "name": "unsafe-switch", "kind": "network-switch", "endpoint": "https://switch.example.test/restconf/data",
            "credential_ref": provider["credential_ref"], "api_version": "openconfig-restconf-1.0",
            "implementation_version": "openconfig-restconf-v1", "site": "dc1", "zone": "rack-a",
            "capabilities": provider["capabilities"],
        },
    )
    assert bad_endpoint.status_code == 422
    assert "IP literal" in bad_endpoint.json()["detail"]

    bad_profile = client.post(
        "/v1/infrastructure-providers", headers=ADMIN,
        json={
            "name": "wrong-profile", "kind": "network-switch", "endpoint": "https://198.51.100.11/restconf/data",
            "credential_ref": provider["credential_ref"], "api_version": "openconfig-restconf-1.0",
            "implementation_version": "openconfig-restconf-v1", "site": "dc1", "zone": "rack-a",
            "capabilities": {**provider["capabilities"], "profile": "generic-restconf"},
        },
    )
    assert bad_profile.status_code == 422
    assert "pinned RESTCONF profile" in bad_profile.json()["detail"]


def test_vlan_ensure_plan_uses_trusted_worker_preview_and_exact_hash_binding(client: TestClient, monkeypatch):
    provider = _switch_provider(client)
    seen = []

    async def fake_post(path, payload):
        seen.append((path, payload))
        preliminary = payload["changeset_plan"]["parameters"]["typed_plan"]
        return _switch_preview(preliminary)

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = _plan(client, provider, "vlan.ensure", {"vlan_id": 100, "name": "prod"})

    assert [path for path, _ in seen] == ["/v1/infrastructure/preview"]
    preliminary = seen[0][1]["changeset_plan"]["parameters"]["typed_plan"]
    plan = planned["operation_plan"]["plan"]
    assert planned["operation_job"]["executor"] == "infrastructure-provider-worker"
    assert plan["runtime"]["state"] == "RUNTIME_CAPABLE"
    assert plan["runtime_preview"]["typed_plan_hash"] == preliminary["plan_hash"]
    assert plan["runtime_preview"]["current_hash"]
    assert plan["credential_material_in_plan"] is False
    assert plan["arbitrary_cli_or_shell"] is False


def test_lldp_observe_plan_is_runtime_capable_and_read_only(client: TestClient, monkeypatch):
    provider = _switch_provider(client)
    seen = []

    async def fake_post(path, payload):
        seen.append(path)
        return _switch_preview(payload["changeset_plan"]["parameters"]["typed_plan"])

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = _plan(client, provider, "lldp.observe", {})
    plan = planned["operation_plan"]["plan"]
    assert seen == ["/v1/infrastructure/preview"]
    assert plan["runtime"]["state"] == "RUNTIME_CAPABLE"
    assert plan["runtime_preview"]["diff"] == []


def test_port_configure_trunk_plan_uses_trusted_worker_preview(client: TestClient, monkeypatch):
    provider = _switch_provider(client)

    async def fake_post(path, payload):
        assert path == "/v1/infrastructure/preview"
        return _switch_preview(payload["changeset_plan"]["parameters"]["typed_plan"])

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = _plan(client, provider, "port.configure", {"port": "Ethernet2", "mode": "trunk", "trunk_vlans": [100, 200]})
    plan = planned["operation_plan"]["plan"]
    assert plan["runtime"]["state"] == "RUNTIME_CAPABLE"
    assert plan["desired_state"] == {"port": "Ethernet2", "mode": "trunk", "trunk_vlans": [100, 200]}


@pytest.mark.parametrize(
    "operation,desired",
    [
        ("vlan.ensure", {"vlan_id": 100, "name": "prod", "command": "raw shell"}),
        ("port.configure", {"port": "Ethernet1", "mode": "access", "access_vlan": 100, "path": "/arbitrary"}),
        ("lldp.observe", {"port": "Ethernet1"}),
    ],
)
def test_invalid_switch_desired_state_fails_before_worker_dispatch(client: TestClient, monkeypatch, operation: str, desired: dict):
    provider = _switch_provider(client)
    called = []

    async def fake_post(path, payload):
        called.append(path)
        raise AssertionError("worker must not be called for invalid switch desired state")

    monkeypatch.setattr(provider_worker, "post", fake_post)
    denied = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:c9", "source_channel": "hermes-bot", "domain": "network",
            "operation": operation, "provider_id": provider["id"], "desired_state": desired,
        },
    )
    assert denied.status_code == 422
    assert called == []


@pytest.mark.parametrize(
    "operation,desired",
    [
        ("vlan.ensure", {"vlan_id": 999, "name": "unapproved"}),
        ("port.configure", {"port": "Ethernet9", "mode": "access", "access_vlan": 100}),
        ("port.configure", {"port": "Ethernet1", "mode": "trunk", "trunk_vlans": [100]}),
        ("port.configure", {"port": "Ethernet2", "mode": "trunk", "trunk_vlans": [100, 999]}),
    ],
)
def test_denied_switch_capability_input_fails_before_worker_dispatch(client: TestClient, monkeypatch, operation: str, desired: dict):
    provider = _switch_provider(client)
    called = []

    async def fake_post(path, payload):
        called.append(path)
        raise AssertionError("worker must not be called for denied switch capability")

    monkeypatch.setattr(provider_worker, "post", fake_post)
    denied = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:c9", "source_channel": "hermes-bot", "domain": "network",
            "operation": operation, "provider_id": provider["id"], "desired_state": desired,
        },
    )
    assert denied.status_code == 422
    assert called == []


@pytest.mark.parametrize(
    "operation,desired",
    [
        ("bond.ensure", {}),
        ("network.attach", {}),
        ("network.detach", {}),
        ("bgp.configure", {}),
    ],
)
def test_deferred_switch_operations_remain_contract_only_without_worker_preview(client: TestClient, monkeypatch, operation: str, desired: dict):
    provider = _switch_provider(client)
    called = []

    async def fake_post(path, payload):
        called.append(path)
        raise AssertionError("contract-only switch operation must not call trusted runtime worker")

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = _plan(client, provider, operation, desired)
    plan = planned["operation_plan"]["plan"]
    assert called == []
    assert planned["operation_job"]["executor"] == "network-switch-provider-worker"
    assert plan["runtime"]["state"] == "CONTRACT_ONLY"
    assert plan["runtime_preview"] is None


def test_execute_persists_network_switch_active_verification(client: TestClient, monkeypatch):
    provider = _switch_provider(client)

    async def fake_post(path, payload):
        if path == "/v1/infrastructure/preview":
            return _switch_preview(payload["changeset_plan"]["parameters"]["typed_plan"])
        assert path == "/v1/infrastructure/execute"
        typed = payload["ticket"]["plan"]["parameters"]["typed_plan"]
        return {
            "state": "SUCCEEDED",
            "provider_kind": "network-switch",
            "operation": typed["operation"],
            "typed_plan_hash": payload["ticket"]["preconditions"]["typed_plan_hash"],
            "verification": {
                "checks": [
                    {"id": "provider-state-drift", "status": "PASS", "summary": "Exact approved preview matched", "evidence": {"provider_id": provider["id"]}},
                    {"id": "network-switch-active-verify", "status": "PASS", "summary": "VLAN converged", "evidence": {"vlan_id": 100, "name": "prod"}},
                ],
                "evidence": {"provider_kind": "network-switch", "arbitrary_cli": False, "arbitrary_shell": False, "raw_credentials_returned": False},
                "observed_at": 1787330000,
            },
        }

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = _plan(client, provider, "vlan.ensure", {"vlan_id": 100, "name": "prod"})
    authorization = _approve_and_authorize(client, planned)
    assert authorization["execution_ticket"]["preconditions"]["executor"] == "infrastructure-provider-worker"
    executed = client.post(
        f"/v1/operation-jobs/{planned['operation_job']['id']}/execute", headers=BOT,
        json={
            "execution_ticket": authorization["execution_ticket"], "signature": authorization["signature"],
            "actor": "hermes-bot:c9",
        },
    )
    assert executed.status_code == 200, executed.text
    body = executed.json()
    assert body["operation_job"]["state"] == "SUCCEEDED"
    assert body["verification"]["status"] == "PASS"
    assert body["infrastructure_worker_result"]["verification"]["checks"][1]["id"] == "network-switch-active-verify"
