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


def _credential(client: TestClient, suffix: str = "") -> str:
    response = client.post(
        "/v1/internal/credential-refs/sync", headers=CREDENTIAL_SERVICE,
        json={
            "id": f"cred_platform12345{suffix}", "name": f"platform-worker{suffix}", "kind": "generic",
            "provider": "credential-service", "status": "configured",
            "metadata": {"scope": "infrastructure-provider-worker"},
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _redfish_provider(client: TestClient) -> dict:
    response = client.post(
        "/v1/infrastructure-providers", headers=ADMIN,
        json={
            "name": "rack-a-platform", "kind": "redfish", "endpoint": "https://bmc.example.test/redfish/v1",
            "credential_ref": _credential(client), "api_version": "1.20.0", "implementation_version": "redfish-http-v1",
            "site": "dc1", "zone": "rack-a",
            "capabilities": {
                "system_id": "System.Embedded.1",
                "bios_attribute_allowlist": ["SriovGlobalEnable", "IommuSupport"],
                "secure_boot": {"activation": "reboot", "reset_type": "GracefulRestart"},
                "hardware_feature_map": {
                    "sriov": {
                        "attribute": "SriovGlobalEnable", "enabled_value": "Enabled", "disabled_value": "Disabled",
                        "activation": "reboot", "reset_type": "GracefulRestart",
                    },
                    "iommu": {
                        "attribute": "IommuSupport", "enabled_value": "Enabled", "disabled_value": "Disabled",
                        "activation": "reboot", "reset_type": "GracefulRestart",
                    },
                },
                "boot_order": {
                    "allowlist": ["Boot0001", "Boot0002", "Boot0003"],
                    "activation": "reboot", "reset_type": "GracefulRestart",
                },
            },
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _preview(preliminary: dict, current: dict) -> dict:
    current_hash = hashlib.sha256(json.dumps(current, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return {
        "kind": "InfrastructureRuntimePreview", "provider_kind": "redfish", "operation": preliminary["operation"],
        "typed_plan_hash": preliminary["plan_hash"], "current": current, "current_hash": current_hash,
        "desired_state": preliminary["desired_state"], "diff": [{"field": "platform", "from": None, "to": preliminary["desired_state"]}],
        "active_probe": True, "credential_material_returned": False, "secret_output_suppressed": True,
        "arbitrary_cli": False, "arbitrary_shell": False,
    }


def test_secure_boot_plan_is_high_risk_trusted_runtime_and_requires_reboot(client: TestClient, monkeypatch):
    provider = _redfish_provider(client)
    calls = []

    async def fake_post(path, payload):
        calls.append(path)
        preliminary = payload["changeset_plan"]["parameters"]["typed_plan"]
        return _preview(preliminary, {"enabled": False, "active_enabled": False, "current_boot": "Disabled"})

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:c7", "source_channel": "hermes-bot", "domain": "bare-metal",
            "operation": "secure-boot.apply", "provider_id": provider["id"],
            "desired_state": {"enabled": True, "activation": "reboot"},
        },
    )
    assert planned.status_code == 201, planned.text
    body = planned.json()
    assert calls == ["/v1/infrastructure/preview"]
    assert body["changeset"]["risk"] == "HIGH"
    assert body["changeset"]["approval_required"] is True
    assert body["operation_job"]["executor"] == "infrastructure-provider-worker"
    assert body["operation_plan"]["plan"]["runtime"]["state"] == "RUNTIME_CAPABLE"

    calls.clear()
    denied = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:c7", "source_channel": "hermes-bot", "domain": "bare-metal",
            "operation": "secure-boot.apply", "provider_id": provider["id"],
            "desired_state": {"enabled": True, "activation": "immediate"},
        },
    )
    assert denied.status_code == 422
    assert "activation must be reboot" in denied.text
    assert calls == []


def test_sriov_and_iommu_require_exact_provider_mappings(client: TestClient, monkeypatch):
    provider = _redfish_provider(client)

    async def fake_post(path, payload):
        preliminary = payload["changeset_plan"]["parameters"]["typed_plan"]
        return _preview(preliminary, {"attribute": "SriovGlobalEnable", "enabled": False, "pending_enabled": False})

    monkeypatch.setattr(provider_worker, "post", fake_post)
    good = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:c7", "source_channel": "hermes-bot", "domain": "bare-metal",
            "operation": "sriov.apply", "provider_id": provider["id"],
            "desired_state": {"enabled": True, "activation": "reboot"},
        },
    )
    assert good.status_code == 201, good.text
    assert good.json()["operation_plan"]["plan"]["runtime"]["state"] == "RUNTIME_CAPABLE"

    denied = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:c7", "source_channel": "hermes-bot", "domain": "bare-metal",
            "operation": "iommu.apply", "provider_id": provider["id"],
            "desired_state": {"enabled": True, "activation": "immediate"},
        },
    )
    assert denied.status_code == 422
    assert "does not match provider capability" in denied.text


def test_boot_order_is_exact_allowlisted_and_runtime_capable(client: TestClient, monkeypatch):
    provider = _redfish_provider(client)
    calls = []

    async def fake_post(path, payload):
        calls.append(path)
        preliminary = payload["changeset_plan"]["parameters"]["typed_plan"]
        return _preview(preliminary, {"order": ["Boot0002", "Boot0001"], "options": []})

    monkeypatch.setattr(provider_worker, "post", fake_post)
    good = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:c7", "source_channel": "hermes-bot", "domain": "bare-metal",
            "operation": "boot-order.apply", "provider_id": provider["id"],
            "desired_state": {"order": ["Boot0001", "Boot0002"], "activation": "reboot"},
        },
    )
    assert good.status_code == 201, good.text
    assert calls == ["/v1/infrastructure/preview"]

    calls.clear()
    bad = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:c7", "source_channel": "hermes-bot", "domain": "bare-metal",
            "operation": "boot-order.apply", "provider_id": provider["id"],
            "desired_state": {"order": ["Boot0001", "Boot9999"], "activation": "reboot"},
        },
    )
    assert bad.status_code == 422
    assert "not allowlisted" in bad.text
    assert calls == []


@pytest.mark.parametrize(
    ("kind", "operation", "desired"),
    [
        ("vmware-workstation", "vm.clone", {"source": "golden-ubuntu", "name": "lab-node-01"}),
    ],
)
def test_requested_vmware_workstation_is_an_explicit_contract_only_plan_target(
    client: TestClient, monkeypatch, kind: str, operation: str, desired: dict,
):
    cred = _credential(client, suffix=kind.replace("-", "")[:8])
    endpoint = "https://workstation.example.test:8697/api"
    provider = client.post(
        "/v1/infrastructure-providers", headers=ADMIN,
        json={
            "name": f"{kind}-lab", "kind": kind, "endpoint": endpoint, "credential_ref": cred,
            "api_version": "workstation-rest-v1",
            "implementation_version": "contract-only-c7", "site": "lab", "zone": "local", "capabilities": {},
        },
    )
    assert provider.status_code == 201, provider.text
    called = []

    async def fake_post(path, payload):
        called.append(path)
        raise AssertionError("contract-only provider must not call trusted runtime worker")

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:c7", "source_channel": "hermes-bot", "domain": "cloud",
            "operation": operation, "provider_id": provider.json()["id"], "desired_state": desired,
        },
    )
    assert planned.status_code == 201, planned.text
    assert called == []
    assert planned.json()["operation_plan"]["plan"]["runtime"]["state"] == "CONTRACT_ONLY"


def _proxmox_provider(client: TestClient) -> dict:
    response = client.post(
        "/v1/infrastructure-providers", headers=ADMIN,
        json={
            "name": "pve-lab", "kind": "proxmox", "endpoint": "https://pve.example.test:8006/api2/json",
            "credential_ref": _credential(client, suffix="proxmoxc7"),
            "api_version": "pve-8.2", "implementation_version": "pve-vm-runtime-v1",
            "site": "lab", "zone": "local",
            "capabilities": {
                "profile": "pve-vm-runtime-v1",
                "node_allowlist": ["pve1"],
                "storage_allowlist": ["local-lvm"],
                "bridge_allowlist": ["vmbr0"],
                "template_allowlist": [{"node": "pve1", "vm_id": 9000}],
                "vm_id_min": 100, "vm_id_max": 999999,
                "max_cpu_cores": 32, "max_memory_mib": 131072, "max_disk_gib": 2048,
                "max_nics": 4, "max_snapshots": 16,
                "action_allowlist": ["vm.clone"],
                "allow_vm_delete": False, "allow_snapshot_restore": False,
            },
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_requested_proxmox_vm_clone_is_runtime_capable_with_pinned_capabilities(client: TestClient, monkeypatch):
    provider = _proxmox_provider(client)
    desired = {
        "source_vm_id": 9000, "source_node": "pve1", "target_vm_id": 9101, "target_node": "pve1",
        "storage": "local-lvm", "name": "lab-node-01",
    }
    calls = []

    async def fake_post(path, payload):
        calls.append(path)
        preliminary = payload["changeset_plan"]["parameters"]["typed_plan"]
        current = {"present": False}
        current_hash = hashlib.sha256(json.dumps(current, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        return {
            "kind": "InfrastructureRuntimePreview", "provider_kind": "proxmox", "operation": preliminary["operation"],
            "typed_plan_hash": preliminary["plan_hash"], "current": current, "current_hash": current_hash,
            "desired_state": preliminary["desired_state"], "diff": [{"field": "vm.presence", "from": "absent", "to": "present"}],
            "active_probe": True, "credential_material_returned": False, "secret_output_suppressed": True,
            "arbitrary_cli": False, "arbitrary_shell": False,
        }

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:c7", "source_channel": "hermes-bot", "domain": "cloud",
            "operation": "vm.clone", "provider_id": provider["id"], "desired_state": desired,
        },
    )
    assert planned.status_code == 201, planned.text
    body = planned.json()
    assert calls == ["/v1/infrastructure/preview"]
    assert body["changeset"]["risk"] == "HIGH"
    assert body["changeset"]["approval_required"] is True
    assert body["operation_plan"]["plan"]["runtime"]["state"] == "RUNTIME_CAPABLE"


def test_requested_proxmox_vm_delete_outside_action_allowlist_is_denied_before_worker_call(client: TestClient, monkeypatch):
    provider = _proxmox_provider(client)
    desired = {"vm_id": 9101, "node": "pve1", "confirm_vm_id": 9101}

    async def fake_post(path, payload):
        raise AssertionError("delete outside action_allowlist must never reach the trusted runtime worker")

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:c7", "source_channel": "hermes-bot", "domain": "cloud",
            "operation": "vm.delete", "provider_id": provider["id"], "desired_state": desired,
        },
    )
    assert planned.status_code == 422
    assert "action_allowlist" in planned.text


def _proxmox_delete_capable_provider(client: TestClient) -> dict:
    response = client.post(
        "/v1/infrastructure-providers", headers=ADMIN,
        json={
            "name": "pve-lab-delete", "kind": "proxmox", "endpoint": "https://pve.example.test:8006/api2/json",
            "credential_ref": _credential(client, suffix="proxmoxdel"),
            "api_version": "pve-8.2", "implementation_version": "pve-vm-runtime-v1",
            "site": "lab", "zone": "local",
            "capabilities": {
                "profile": "pve-vm-runtime-v1",
                "node_allowlist": ["pve1"],
                "storage_allowlist": ["local-lvm"],
                "bridge_allowlist": ["vmbr0"],
                "template_allowlist": [],
                "vm_id_min": 100, "vm_id_max": 999999,
                "max_cpu_cores": 32, "max_memory_mib": 131072, "max_disk_gib": 2048,
                "max_nics": 4, "max_snapshots": 16,
                "action_allowlist": ["vm.delete", "snapshot.restore"],
                "allow_vm_delete": True, "allow_snapshot_restore": True,
            },
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_requested_proxmox_vm_delete_is_critical_and_requires_two_approvals(client: TestClient, monkeypatch):
    provider = _proxmox_delete_capable_provider(client)
    desired = {"vm_id": 9101, "node": "pve1", "confirm_vm_id": 9101}

    async def fake_post(path, payload):
        preliminary = payload["changeset_plan"]["parameters"]["typed_plan"]
        current = {
            "present": True, "node": "pve1", "vm_id": 9101, "qemu": True, "power_state": "stopped",
            "cpu_cores": 2, "memory_mib": 2048, "onboot": False,
            "disk": {"storage": "local-lvm", "size_gib": 32}, "networks": {}, "snapshots": [],
        }
        current_hash = hashlib.sha256(json.dumps(current, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        return {
            "kind": "InfrastructureRuntimePreview", "provider_kind": "proxmox", "operation": preliminary["operation"],
            "typed_plan_hash": preliminary["plan_hash"], "current": current, "current_hash": current_hash,
            "desired_state": preliminary["desired_state"], "diff": [{"field": "vm.presence", "from": "present", "to": "absent"}],
            "active_probe": True, "credential_material_returned": False, "secret_output_suppressed": True,
            "arbitrary_cli": False, "arbitrary_shell": False,
        }

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:c7", "source_channel": "hermes-bot", "domain": "cloud",
            "operation": "vm.delete", "provider_id": provider["id"], "desired_state": desired,
        },
    )
    assert planned.status_code == 201, planned.text
    body = planned.json()
    assert body["changeset"]["risk"] == "CRITICAL"
    assert body["changeset"]["approval_required"] is True
    assert body["operation_plan"]["plan"]["runtime"]["state"] == "RUNTIME_CAPABLE"

    assert client.post(f"/v1/changesets/{body['changeset']['id']}/request-approval", headers=BOT).status_code == 200
    first = client.post(
        f"/v1/changesets/{body['changeset']['id']}/approve", headers=APPROVAL,
        json={"approver": "approval-bot:delete-a", "plan_hash": body["changeset"]["plan_hash"]},
    )
    assert first.status_code == 201, first.text
    assert first.json()["required_approvals"] == 2
    assert first.json()["changeset_state"] == "AWAITING_APPROVAL"
    blocked = client.post(f"/v1/operation-jobs/{body['operation_job']['id']}/authorize", headers=BOT)
    assert blocked.status_code == 409

    second = client.post(
        f"/v1/changesets/{body['changeset']['id']}/approve", headers=APPROVAL,
        json={"approver": "approval-bot:delete-b", "plan_hash": body["changeset"]["plan_hash"]},
    )
    assert second.status_code == 201, second.text
    assert second.json()["required_approvals"] == 2
    assert second.json()["changeset_state"] == "APPROVED"


def test_requested_proxmox_snapshot_restore_denied_when_capability_flag_is_false(client: TestClient, monkeypatch):
    provider = _proxmox_provider(client)
    desired = {"vm_id": 9101, "node": "pve1", "snapshot": "pre-upgrade", "confirm_vm_id": 9101, "confirm_snapshot": "pre-upgrade"}

    async def fake_post(path, payload):
        raise AssertionError("snapshot.restore outside action_allowlist must never reach the trusted runtime worker")

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:c7", "source_channel": "hermes-bot", "domain": "cloud",
            "operation": "snapshot.restore", "provider_id": provider["id"], "desired_state": desired,
        },
    )
    assert planned.status_code == 422
    assert "action_allowlist" in planned.text
