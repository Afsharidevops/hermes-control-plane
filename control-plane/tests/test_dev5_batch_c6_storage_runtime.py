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


def _provider(client: TestClient, *, allow_delete: bool = True, suffix: str = "") -> dict:
    cred = client.post(
        "/v1/internal/credential-refs/sync", headers=CREDENTIAL_SERVICE,
        json={"id": f"cred_storage12345{suffix}", "name": f"storage-worker{suffix}", "kind": "generic", "provider": "credential-service", "status": "configured", "metadata": {"scope": "infrastructure-provider-worker"}},
    )
    assert cred.status_code == 200, cred.text
    response = client.post(
        "/v1/infrastructure-providers", headers=ADMIN,
        json={
            "name": f"rack-a-storage{suffix}", "kind": "redfish", "endpoint": "https://bmc.example.test/redfish/v1",
            "credential_ref": cred.json()["id"], "api_version": "1.20.0", "implementation_version": "redfish-http-v1",
            "site": "dc1", "zone": "rack-a",
            "capabilities": {
                "system_id": "System.Embedded.1",
                "storage_controller_allowlist": {
                    "RAID.Integrated.1-1": {
                        "drive_ids": ["Disk.Bay.0", "Disk.Bay.1", "Disk.Bay.2", "Disk.Bay.3"],
                        "raid_types": ["RAID1", "RAID10"],
                        "volume_names": ["os-mirror", "data-mirror"],
                        "allow_volume_delete": allow_delete,
                    }
                },
            },
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _apply_desired() -> dict:
    return {"controller_id": "RAID.Integrated.1-1", "volume_name": "os-mirror", "raid_type": "RAID1", "drive_ids": ["Disk.Bay.0", "Disk.Bay.1"]}


def _preview(preliminary: dict) -> dict:
    desired = preliminary["desired_state"]
    current = {
        "controller_id": desired["controller_id"], "controller_name": "PERC H755N Front",
        "drives": [
            {"id": "Disk.Bay.0", "name": "NVMe 0", "serial_number": "SERIAL-0", "part_number": "PN", "model": "EXAMPLE", "media_type": "SSD", "protocol": "NVMe", "capacity_bytes": 1000, "health": "OK", "state": "Enabled"},
            {"id": "Disk.Bay.1", "name": "NVMe 1", "serial_number": "SERIAL-1", "part_number": "PN", "model": "EXAMPLE", "media_type": "SSD", "protocol": "NVMe", "capacity_bytes": 1000, "health": "OK", "state": "Enabled"},
        ],
        "volumes": [],
    }
    current_hash = hashlib.sha256(json.dumps(current, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return {
        "kind": "InfrastructureRuntimePreview", "provider_kind": "redfish", "operation": preliminary["operation"],
        "typed_plan_hash": preliminary["plan_hash"], "current": current, "current_hash": current_hash,
        "desired_state": desired, "diff": [{"field": "storage.volume", "from": None, "to": desired}],
        "active_probe": True, "credential_material_returned": False, "secret_output_suppressed": True,
        "arbitrary_cli": False, "arbitrary_shell": False,
    }


def test_storage_apply_plan_is_trusted_runtime_and_high_risk(client: TestClient, monkeypatch):
    provider = _provider(client)
    calls = []

    async def fake_post(path, payload):
        calls.append(path)
        return _preview(payload["changeset_plan"]["parameters"]["typed_plan"])

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={"requested_by": "hermes-bot:storage", "source_channel": "hermes-bot", "domain": "bare-metal", "operation": "storage.volume.apply", "provider_id": provider["id"], "desired_state": _apply_desired()},
    )
    assert planned.status_code == 201, planned.text
    body = planned.json()
    assert calls == ["/v1/infrastructure/preview"]
    assert body["operation_job"]["executor"] == "infrastructure-provider-worker"
    assert body["operation_plan"]["plan"]["runtime"]["state"] == "RUNTIME_CAPABLE"
    assert body["changeset"]["risk"] == "HIGH"
    assert body["changeset"]["approval_required"] is True


def test_storage_apply_rejects_non_allowlisted_drive_before_worker(client: TestClient, monkeypatch):
    provider = _provider(client)
    called = []

    async def fake_post(path, payload):
        called.append(path)
        raise AssertionError("worker must not be called")

    monkeypatch.setattr(provider_worker, "post", fake_post)
    desired = _apply_desired()
    desired["drive_ids"] = ["Disk.Bay.0", "Disk.Bay.99"]
    denied = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={"requested_by": "hermes-bot:storage", "source_channel": "hermes-bot", "domain": "bare-metal", "operation": "storage.volume.apply", "provider_id": provider["id"], "desired_state": desired},
    )
    assert denied.status_code == 422
    assert "not allowlisted" in denied.text
    assert called == []


def test_storage_delete_is_critical_and_requires_explicit_capability(client: TestClient, monkeypatch):
    provider = _provider(client, allow_delete=True)

    async def fake_post(path, payload):
        preliminary = payload["changeset_plan"]["parameters"]["typed_plan"]
        current = {"controller_id": "RAID.Integrated.1-1", "controller_name": "PERC", "drives": [], "volumes": [{"id": "vol-os", "name": "os-mirror", "raid_type": "RAID1", "capacity_bytes": 1000, "drive_ids": ["Disk.Bay.0", "Disk.Bay.1"], "health": "OK", "state": "Enabled"}]}
        current_hash = hashlib.sha256(json.dumps(current, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        return {"kind": "InfrastructureRuntimePreview", "provider_kind": "redfish", "operation": preliminary["operation"], "typed_plan_hash": preliminary["plan_hash"], "current": current, "current_hash": current_hash, "desired_state": preliminary["desired_state"], "diff": [{"field": "storage.volume.vol-os", "from": current["volumes"][0], "to": None}], "active_probe": True, "credential_material_returned": False, "secret_output_suppressed": True, "arbitrary_cli": False, "arbitrary_shell": False}

    monkeypatch.setattr(provider_worker, "post", fake_post)
    desired = {"controller_id": "RAID.Integrated.1-1", "volume_id": "vol-os", "confirm_volume_id": "vol-os"}
    planned = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={"requested_by": "hermes-bot:storage", "source_channel": "hermes-bot", "domain": "bare-metal", "operation": "storage.volume.delete", "provider_id": provider["id"], "desired_state": desired},
    )
    assert planned.status_code == 201, planned.text
    assert planned.json()["changeset"]["risk"] == "CRITICAL"
    assert planned.json()["changeset"]["approval_required"] is True

    disabled = _provider(client, allow_delete=False, suffix="x")
    denied = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={"requested_by": "hermes-bot:storage", "source_channel": "hermes-bot", "domain": "bare-metal", "operation": "storage.volume.delete", "provider_id": disabled["id"], "desired_state": desired},
    )
    assert denied.status_code == 422
    assert "deletion is disabled" in denied.text


def test_storage_delete_confirmation_must_match_exact_volume_id(client: TestClient, monkeypatch):
    provider = _provider(client)
    called = []

    async def fake_post(path, payload):
        called.append(path)
        raise AssertionError("worker must not be called")

    monkeypatch.setattr(provider_worker, "post", fake_post)
    denied = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={"requested_by": "hermes-bot:storage", "source_channel": "hermes-bot", "domain": "bare-metal", "operation": "storage.volume.delete", "provider_id": provider["id"], "desired_state": {"controller_id": "RAID.Integrated.1-1", "volume_id": "vol-os", "confirm_volume_id": "vol-other"}},
    )
    assert denied.status_code == 422
    assert called == []
