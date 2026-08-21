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


def _provider(client: TestClient) -> dict:
    cred = client.post(
        "/v1/internal/credential-refs/sync", headers=CREDENTIAL_SERVICE,
        json={
            "id": "cred_redfish12345", "name": "redfish-worker", "kind": "generic",
            "provider": "credential-service", "status": "configured",
            "metadata": {"scope": "infrastructure-provider-worker"},
        },
    )
    assert cred.status_code == 200, cred.text
    response = client.post(
        "/v1/infrastructure-providers", headers=ADMIN,
        json={
            "name": "rack-a-bmc", "kind": "redfish", "endpoint": "https://bmc.example.test/redfish/v1",
            "credential_ref": cred.json()["id"], "api_version": "1.20.0", "implementation_version": "redfish-http-v1",
            "site": "dc1", "zone": "rack-a", "capabilities": {"system_id": "System.Embedded.1", "manager_id": "iDRAC.Embedded.1", "virtual_media_id": "CD", "virtual_media_image_hosts": ["repo.example.test"], "bios_attribute_allowlist": ["BootMode", "SriovGlobalEnable"], "firmware_image_hosts": ["firmware.example.test"], "firmware_component_allowlist": ["BMC", "BIOS"]},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _approve(client: TestClient, changeset: dict) -> None:
    assert client.post(f"/v1/changesets/{changeset['id']}/request-approval", headers=BOT).status_code == 200
    approved = client.post(
        f"/v1/changesets/{changeset['id']}/approve", headers=APPROVAL,
        json={"approver": "approval-bot:batch-c", "plan_hash": changeset["plan_hash"]},
    )
    assert approved.status_code == 201, approved.text


def _preview(preliminary: dict) -> dict:
    current = {
        "resource_id": "System.Embedded.1", "name": "PowerEdge", "manufacturer": "Example", "model": "R760",
        "serial_number": "SERIAL123", "power_state": "On", "health": "OK", "state": "Enabled",
        "boot_target": "Hdd", "boot_enabled": "Disabled", "boot_mode": "UEFI",
    }
    import hashlib, json
    current_hash = hashlib.sha256(json.dumps(current, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return {
        "kind": "InfrastructureRuntimePreview", "provider_kind": "redfish", "operation": preliminary["operation"],
        "typed_plan_hash": preliminary["plan_hash"], "current": current, "current_hash": current_hash,
        "desired_state": preliminary["desired_state"], "diff": [{"field": "power_state", "from": "On", "to": "force-off"}],
        "active_probe": True, "credential_material_returned": False, "secret_output_suppressed": True,
        "arbitrary_cli": False, "arbitrary_shell": False,
    }


def test_redfish_plan_calls_trusted_preview_and_binds_runtime(client: TestClient, monkeypatch):
    provider = _provider(client)
    seen = []

    async def fake_post(path, payload):
        seen.append((path, payload))
        preliminary = payload["changeset_plan"]["parameters"]["typed_plan"]
        return _preview(preliminary)

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:batch-c", "source_channel": "hermes-bot", "domain": "bare-metal",
            "operation": "power.set", "provider_id": provider["id"], "desired_state": {"state": "force-off"},
        },
    )
    assert planned.status_code == 201, planned.text
    body = planned.json()
    assert seen[0][0] == "/v1/infrastructure/preview"
    assert body["operation_job"]["executor"] == "infrastructure-provider-worker"
    plan = body["operation_plan"]["plan"]
    assert plan["runtime"]["state"] == "RUNTIME_CAPABLE"
    assert plan["runtime_preview"]["active_probe"] is True
    assert plan["credential_material_in_plan"] is False
    assert plan["arbitrary_cli_or_shell"] is False


def test_redfish_execute_routes_signed_ticket_to_worker_and_records_active_verification(client: TestClient, monkeypatch):
    provider = _provider(client)

    async def fake_post(path, payload):
        if path == "/v1/infrastructure/preview":
            return _preview(payload["changeset_plan"]["parameters"]["typed_plan"])
        assert path == "/v1/infrastructure/execute"
        return {
            "state": "SUCCEEDED", "provider_kind": "redfish", "operation": "power.set",
            "typed_plan_hash": payload["ticket"]["preconditions"]["typed_plan_hash"],
            "verification": {
                "checks": [
                    {"id": "provider-state-drift", "status": "PASS", "summary": "Exact approved preview matched", "evidence": {"provider_id": provider["id"]}},
                    {"id": "redfish-active-verify", "status": "PASS", "summary": "Power state converged", "evidence": {"power_state": "Off"}},
                ],
                "evidence": {"provider_kind": "redfish", "arbitrary_cli": False, "raw_credentials_returned": False},
                "observed_at": 1787330000,
            },
        }

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:batch-c", "source_channel": "hermes-bot", "domain": "bare-metal",
            "operation": "power.set", "provider_id": provider["id"], "desired_state": {"state": "force-off"},
        },
    ).json()
    _approve(client, planned["changeset"])
    auth = client.post(f"/v1/operation-jobs/{planned['operation_job']['id']}/authorize", headers=BOT)
    assert auth.status_code == 200, auth.text
    assert auth.json()["execution_ticket"]["preconditions"]["executor"] == "infrastructure-provider-worker"
    executed = client.post(
        f"/v1/operation-jobs/{planned['operation_job']['id']}/execute", headers=BOT,
        json={"execution_ticket": auth.json()["execution_ticket"], "signature": auth.json()["signature"], "actor": "hermes-bot:batch-c"},
    )
    assert executed.status_code == 200, executed.text
    assert executed.json()["operation_job"]["state"] == "SUCCEEDED"
    assert executed.json()["verification"]["status"] == "PASS"
    assert executed.json()["infrastructure_worker_result"]["verification"]["checks"][1]["id"] == "redfish-active-verify"


def test_redfish_rejects_unbounded_desired_state_before_worker_call(client: TestClient, monkeypatch):
    provider = _provider(client)
    called = []

    async def fake_post(path, payload):
        called.append(path)
        raise AssertionError("worker should not be called")

    monkeypatch.setattr(provider_worker, "post", fake_post)
    denied = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:batch-c", "source_channel": "hermes-bot", "domain": "bare-metal",
            "operation": "power.set", "provider_id": provider["id"],
            "desired_state": {"state": "on", "command": "arbitrary raw command"},
        },
    )
    assert denied.status_code == 422
    assert called == []


def test_non_redfish_provider_remains_contract_only_without_worker_preview(client: TestClient, monkeypatch):
    cred = client.post(
        "/v1/internal/credential-refs/sync", headers=CREDENTIAL_SERVICE,
        json={
            "id": "cred_awsprovider123", "name": "aws-worker", "kind": "generic",
            "provider": "credential-service", "status": "configured",
            "metadata": {"scope": "infrastructure-provider-worker"},
        },
    )
    assert cred.status_code == 200, cred.text
    provider = client.post(
        "/v1/infrastructure-providers", headers=ADMIN,
        json={
            "name": "aws-dev", "kind": "aws", "endpoint": "https://ec2.us-east-1.amazonaws.com",
            "credential_ref": cred.json()["id"], "api_version": "2016-11-15", "implementation_version": "boto3-pinned-v1",
            "site": "us-east-1", "zone": "us-east-1a", "capabilities": {},
        },
    )
    assert provider.status_code == 201, provider.text
    called = []

    async def fake_post(path, payload):
        called.append(path)
        raise AssertionError("contract-only cloud provider must not call trusted runtime worker")

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:batch-c", "source_channel": "hermes-bot", "domain": "cloud",
            "operation": "vm.power", "provider_id": provider.json()["id"], "desired_state": {},
        },
    )
    assert planned.status_code == 201, planned.text
    body = planned.json()
    assert called == []
    assert body["operation_job"]["executor"] == "aws-provider-worker"
    assert body["operation_plan"]["plan"]["runtime"]["state"] == "CONTRACT_ONLY"


def test_redfish_virtual_media_plan_uses_trusted_runtime_and_rejects_url_credentials(client: TestClient, monkeypatch):
    provider = _provider(client)
    seen = []

    async def fake_post(path, payload):
        seen.append(path)
        preliminary = payload["changeset_plan"]["parameters"]["typed_plan"]
        current = {
            "resource_id": "CD", "name": "Virtual CD", "inserted": False, "write_protected": True,
            "image_present": False, "image_url": "", "image_sha256": "", "media_types": ["CD", "DVD"], "connected_via": "URI",
        }
        import hashlib, json
        current_hash = hashlib.sha256(json.dumps(current, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        return {
            "kind": "InfrastructureRuntimePreview", "provider_kind": "redfish", "operation": preliminary["operation"],
            "typed_plan_hash": preliminary["plan_hash"], "current": current, "current_hash": current_hash,
            "desired_state": preliminary["desired_state"], "diff": [{"field": "inserted", "from": False, "to": True}],
            "active_probe": True, "credential_material_returned": False, "secret_output_suppressed": True,
            "arbitrary_cli": False, "arbitrary_shell": False,
        }

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:batch-c", "source_channel": "hermes-bot", "domain": "bare-metal",
            "operation": "virtual-media.insert", "provider_id": provider["id"],
            "desired_state": {"image_url": "https://repo.example.test/images/node.iso", "write_protected": True},
        },
    )
    assert planned.status_code == 201, planned.text
    assert seen == ["/v1/infrastructure/preview"]
    assert planned.json()["operation_job"]["executor"] == "infrastructure-provider-worker"
    assert planned.json()["operation_plan"]["plan"]["runtime"]["state"] == "RUNTIME_CAPABLE"

    seen.clear()
    rejected = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:batch-c", "source_channel": "hermes-bot", "domain": "bare-metal",
            "operation": "virtual-media.insert", "provider_id": provider["id"],
            "desired_state": {"image_url": "https://repo.example.test/images/node.iso?token=secret"},
        },
    )
    assert rejected.status_code == 422
    assert seen == []


def test_redfish_bios_plan_uses_runtime_and_rejects_structured_attribute_values(client: TestClient, monkeypatch):
    provider = _provider(client)
    seen = []

    async def fake_post(path, payload):
        seen.append(path)
        preliminary = payload["changeset_plan"]["parameters"]["typed_plan"]
        current = {
            "resource_id": "Bios", "name": "BIOS Configuration Current Settings",
            "attributes": {"BootMode": "Uefi", "SriovGlobalEnable": "Disabled"}, "attribute_count": 2,
        }
        import hashlib, json
        current_hash = hashlib.sha256(json.dumps(current, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        return {
            "kind": "InfrastructureRuntimePreview", "provider_kind": "redfish", "operation": preliminary["operation"],
            "typed_plan_hash": preliminary["plan_hash"], "current": current, "current_hash": current_hash,
            "desired_state": preliminary["desired_state"],
            "diff": [{"field": "bios.BootMode", "from": "Uefi", "to": "Bios"}],
            "active_probe": True, "credential_material_returned": False, "secret_output_suppressed": True,
            "arbitrary_cli": False, "arbitrary_shell": False,
        }

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:batch-c", "source_channel": "hermes-bot", "domain": "bare-metal",
            "operation": "bios.apply", "provider_id": provider["id"],
            "desired_state": {"attributes": {"BootMode": "Bios", "SriovGlobalEnable": "Enabled"}},
        },
    )
    assert planned.status_code == 201, planned.text
    assert seen == ["/v1/infrastructure/preview"]
    assert planned.json()["operation_job"]["executor"] == "infrastructure-provider-worker"
    assert planned.json()["operation_plan"]["plan"]["runtime"]["state"] == "RUNTIME_CAPABLE"

    seen.clear()
    rejected = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:batch-c", "source_channel": "hermes-bot", "domain": "bare-metal",
            "operation": "bios.apply", "provider_id": provider["id"],
            "desired_state": {"attributes": {"BootMode": {"command": "raw"}}},
        },
    )
    assert rejected.status_code == 422
    assert seen == []


def test_redfish_firmware_plan_uses_runtime_and_rejects_unsafe_image_url(client: TestClient, monkeypatch):
    provider = _provider(client)
    seen = []

    async def fake_post(path, payload):
        seen.append(path)
        preliminary = payload["changeset_plan"]["parameters"]["typed_plan"]
        current = {
            "resource_id": "BMC", "name": "Integrated Remote Access Controller", "software_id": "BMC-FW",
            "version": "6.10.30.00", "updateable": True, "health": "OK", "state": "Enabled",
        }
        import hashlib, json
        current_hash = hashlib.sha256(json.dumps(current, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        return {
            "kind": "InfrastructureRuntimePreview", "provider_kind": "redfish", "operation": preliminary["operation"],
            "typed_plan_hash": preliminary["plan_hash"], "current": current, "current_hash": current_hash,
            "desired_state": preliminary["desired_state"],
            "diff": [{"field": "firmware.BMC.version", "from": "6.10.30.00", "to": "7.00.00.00"}],
            "active_probe": True, "credential_material_returned": False, "secret_output_suppressed": True,
            "arbitrary_cli": False, "arbitrary_shell": False,
        }

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:batch-c", "source_channel": "hermes-bot", "domain": "bare-metal",
            "operation": "firmware.apply", "provider_id": provider["id"],
            "desired_state": {
                "image_url": "https://firmware.example.test/redfish/idrac-7.00.bin",
                "component_id": "BMC", "expected_version": "7.00.00.00",
            },
        },
    )
    assert planned.status_code == 201, planned.text
    assert seen == ["/v1/infrastructure/preview"]
    assert planned.json()["operation_job"]["executor"] == "infrastructure-provider-worker"
    assert planned.json()["operation_plan"]["plan"]["runtime"]["state"] == "RUNTIME_CAPABLE"

    seen.clear()
    rejected = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:batch-c", "source_channel": "hermes-bot", "domain": "bare-metal",
            "operation": "firmware.apply", "provider_id": provider["id"],
            "desired_state": {
                "image_url": "https://firmware.example.test/fw.bin?token=secret",
                "component_id": "BMC", "expected_version": "7.00.00.00",
            },
        },
    )
    assert rejected.status_code == 422
    assert seen == []


def _ipmi_provider(client: TestClient) -> dict:
    cred = client.post(
        "/v1/internal/credential-refs/sync", headers=CREDENTIAL_SERVICE,
        json={
            "id": "cred_ipmi12345", "name": "ipmi-worker", "kind": "generic",
            "provider": "credential-service", "status": "configured",
            "metadata": {"scope": "infrastructure-provider-worker"},
        },
    )
    assert cred.status_code == 200, cred.text
    response = client.post(
        "/v1/infrastructure-providers", headers=ADMIN,
        json={
            "name": "rack-a-ipmi", "kind": "ipmi", "endpoint": "ipmi://192.0.2.45:623",
            "credential_ref": cred.json()["id"], "api_version": "ipmi-2.0", "implementation_version": "ipmitool-lanplus-v1",
            "site": "dc1", "zone": "rack-a", "capabilities": {"transport": "lanplus", "fallback_only": True},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_ipmi_plan_calls_trusted_preview_and_remains_fixed_operation_only(client: TestClient, monkeypatch):
    provider = _ipmi_provider(client)
    seen = []

    async def fake_post(path, payload):
        seen.append(path)
        preliminary = payload["changeset_plan"]["parameters"]["typed_plan"]
        current = {
            "resource_id": "ipmi-chassis", "name": "IPMI chassis", "manufacturer": "", "model": "",
            "serial_number": "", "power_state": "On", "last_reset_time": "", "boot_progress": "",
            "boot_progress_time": "", "health": "UNKNOWN", "state": "Enabled",
            "boot_target": "", "boot_enabled": "", "boot_mode": "",
        }
        import hashlib, json
        current_hash = hashlib.sha256(json.dumps(current, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        return {
            "kind": "InfrastructureRuntimePreview", "provider_kind": "ipmi", "operation": preliminary["operation"],
            "typed_plan_hash": preliminary["plan_hash"], "current": current, "current_hash": current_hash,
            "desired_state": preliminary["desired_state"],
            "diff": [{"field": "power_state", "from": "On", "to": "force-off"}],
            "active_probe": True, "credential_material_returned": False, "secret_output_suppressed": True,
            "arbitrary_cli": False, "arbitrary_shell": False,
        }

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:batch-c5a", "source_channel": "hermes-bot", "domain": "bare-metal",
            "operation": "power.set", "provider_id": provider["id"], "desired_state": {"state": "force-off"},
        },
    )
    assert planned.status_code == 201, planned.text
    body = planned.json()
    assert seen == ["/v1/infrastructure/preview"]
    assert body["operation_job"]["executor"] == "infrastructure-provider-worker"
    plan = body["operation_plan"]["plan"]
    assert plan["provider"]["kind"] == "ipmi"
    assert plan["runtime"]["state"] == "RUNTIME_CAPABLE"
    assert plan["arbitrary_cli_or_shell"] is False


def test_ipmi_rejects_arbitrary_command_and_unsupported_graceful_restart_before_worker(client: TestClient, monkeypatch):
    provider = _ipmi_provider(client)
    called = []

    async def fake_post(path, payload):
        called.append(path)
        raise AssertionError("worker should not be called")

    monkeypatch.setattr(provider_worker, "post", fake_post)
    for desired in (
        {"state": "on", "command": "raw ipmitool"},
        {"state": "graceful-restart"},
        {"state": "restart"},
        {"state": "power-cycle"},
    ):
        denied = client.post(
            "/v1/operations-center/intents/plan", headers=BOT,
            json={
                "requested_by": "hermes-bot:batch-c5a", "source_channel": "hermes-bot", "domain": "bare-metal",
                "operation": "power.set", "provider_id": provider["id"], "desired_state": desired,
            },
        )
        assert denied.status_code == 422
    assert called == []
