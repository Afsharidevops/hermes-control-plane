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
        ("proxmox", "vm.clone", {"source": "golden-ubuntu", "name": "lab-node-01"}),
        ("vmware-workstation", "vm.clone", {"source": "golden-ubuntu", "name": "lab-node-01"}),
    ],
)
def test_requested_proxmox_and_vmware_workstation_are_explicit_contract_only_plan_targets(
    client: TestClient, monkeypatch, kind: str, operation: str, desired: dict,
):
    cred = _credential(client, suffix=kind.replace("-", "")[:8])
    endpoint = "https://pve.example.test:8006/api2/json" if kind == "proxmox" else "https://workstation.example.test:8697/api"
    provider = client.post(
        "/v1/infrastructure-providers", headers=ADMIN,
        json={
            "name": f"{kind}-lab", "kind": kind, "endpoint": endpoint, "credential_ref": cred,
            "api_version": "pve-api-v2" if kind == "proxmox" else "workstation-rest-v1",
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
