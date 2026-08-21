from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest
from fastapi import HTTPException

from hermes_node_agent import infrastructure_runtime as runtime




def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _signed_ticket(typed: dict, key: str):
    plan = {"parameters": {"typed_plan": typed}}
    ticket = {
        "changeset_id": "chg_storage01234567",
        "plan_hash": runtime.sha256_hex(plan),
        "plan": plan,
        "preconditions": {
            "operation_job_id": "opj_storage01234567",
            "operation_plan_id": "opn_storage01234567",
            "executor": "infrastructure-provider-worker",
            "typed_plan_hash": typed["plan_hash"],
            "policy_generation": 1,
        },
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + 120,
    }
    signature = hmac.new(key.encode(), _canonical(ticket).encode(), hashlib.sha256).hexdigest()
    return ticket, signature

def _hashed(snapshot: dict) -> dict:
    snapshot = dict(snapshot)
    snapshot["snapshot_hash"] = runtime.sha256_hex(snapshot)
    return snapshot


def _provider(*, allow_delete: bool = True) -> dict:
    return _hashed({
        "id": "ipr_storage12345678",
        "name": "rack-a-bmc",
        "kind": "redfish",
        "endpoint": "https://bmc.example.test/redfish/v1",
        "credential_ref": "cred_redfish12345",
        "credential_snapshot": {"id": "cred_redfish12345", "kind": "generic", "status": "configured", "metadata": {}},
        "api_version": "1.20.0",
        "implementation_version": "redfish-http-v1",
        "site": "dc1",
        "zone": "rack-a",
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
        "labels": {},
        "health_status": "HEALTHY",
        "status": "configured",
    })


def _desired_apply() -> dict:
    return {
        "controller_id": "RAID.Integrated.1-1",
        "volume_name": "os-mirror",
        "raid_type": "RAID1",
        "drive_ids": ["Disk.Bay.0", "Disk.Bay.1"],
    }


def _typed(desired: dict, operation: str, *, provider: dict | None = None, runtime_preview: dict | None = None) -> dict:
    provider = provider or _provider()
    typed = {
        "schema_version": 5,
        "kind": "RedfishBareMetalPlan",
        "operation": operation,
        "provider": {
            "id": provider["id"], "kind": "redfish", "api_version": provider["api_version"],
            "implementation_version": provider["implementation_version"], "credential_ref": provider["credential_ref"],
            "snapshot_hash": provider["snapshot_hash"],
        },
        "targets": [provider],
        "desired_state": desired,
        "runtime_preview": runtime_preview,
    }
    typed["plan_hash"] = runtime.sha256_hex(typed)
    return typed


def _storage_responses(*, with_volume: dict | None = None) -> dict[str, dict]:
    root = "https://bmc.example.test/redfish/v1"
    system = root + "/Systems/System.Embedded.1"
    storage_collection = system + "/Storage"
    controller = storage_collection + "/RAID.Integrated.1-1"
    volumes = controller + "/Volumes"
    mapping: dict[str, dict] = {
        root: {"Systems": {"@odata.id": "/redfish/v1/Systems"}},
        root + "/Systems": {"Members": [{"@odata.id": "/redfish/v1/Systems/System.Embedded.1"}]},
        system: {"Id": "System.Embedded.1", "Storage": {"@odata.id": "/redfish/v1/Systems/System.Embedded.1/Storage"}},
        storage_collection: {"Members": [{"@odata.id": "/redfish/v1/Systems/System.Embedded.1/Storage/RAID.Integrated.1-1"}]},
        controller: {
            "Id": "RAID.Integrated.1-1", "Name": "PERC H755N Front",
            "Drives": [
                {"@odata.id": "/redfish/v1/Systems/System.Embedded.1/Storage/RAID.Integrated.1-1/Drives/Disk.Bay.0"},
                {"@odata.id": "/redfish/v1/Systems/System.Embedded.1/Storage/RAID.Integrated.1-1/Drives/Disk.Bay.1"},
                {"@odata.id": "/redfish/v1/Systems/System.Embedded.1/Storage/RAID.Integrated.1-1/Drives/Disk.Bay.2"},
                {"@odata.id": "/redfish/v1/Systems/System.Embedded.1/Storage/RAID.Integrated.1-1/Drives/Disk.Bay.3"},
            ],
            "Volumes": {"@odata.id": "/redfish/v1/Systems/System.Embedded.1/Storage/RAID.Integrated.1-1/Volumes"},
        },
        volumes: {"Members": []},
    }
    for index in range(4):
        drive_id = f"Disk.Bay.{index}"
        mapping[controller + f"/Drives/{drive_id}"] = {
            "Id": drive_id, "Name": f"NVMe {index}", "SerialNumber": f"SERIAL-DISK-{index}",
            "PartNumber": "PN-123", "Model": "EXAMPLE-NVME", "MediaType": "SSD", "Protocol": "NVMe",
            "CapacityBytes": 1_920_000_000_000, "Status": {"Health": "OK", "State": "Enabled"},
        }
    if with_volume is not None:
        volume_id = str(with_volume["Id"])
        volume_url = volumes + "/" + volume_id
        mapping[volumes] = {"Members": [{"@odata.id": volume_url}]}
        mapping[volume_url] = with_volume
    return mapping


def _patch_requests(monkeypatch, responses: dict[str, dict], calls: list[tuple[str, str, dict | None]]):
    def fake_request(method: str, url: str, *, credential: dict, body: dict | None = None):
        calls.append((method, url, body))
        if method in {"POST", "DELETE", "PATCH"}:
            return {}
        assert method == "GET"
        assert url in responses, url
        return json.loads(json.dumps(responses[url]))

    monkeypatch.setattr(runtime, "_request_json", fake_request)
    monkeypatch.setattr(runtime, "_credential_profile", lambda ref: {"username": "worker-user", "password": "worker-password", "ca_file": None})


def test_storage_preview_binds_exact_physical_drive_identity(monkeypatch):
    calls: list[tuple[str, str, dict | None]] = []
    _patch_requests(monkeypatch, _storage_responses(), calls)
    typed = _typed(_desired_apply(), "storage.volume.apply")
    preview = runtime.preview({"parameters": {"typed_plan": typed}})
    assert preview["provider_kind"] == "redfish"
    assert preview["operation"] == "storage.volume.apply"
    assert preview["active_probe"] is True
    assert preview["current_hash"] == runtime.sha256_hex(preview["current"])
    assert [item["id"] for item in preview["current"]["drives"]] == ["Disk.Bay.0", "Disk.Bay.1", "Disk.Bay.2", "Disk.Bay.3"]
    assert preview["current"]["drives"][0]["serial_number"] == "SERIAL-DISK-0"
    assert preview["diff"][0]["to"]["raid_type"] == "RAID1"
    encoded = json.dumps(preview, sort_keys=True)
    assert "worker-password" not in encoded
    assert "Authorization" not in encoded


def test_storage_apply_uses_fixed_redfish_volume_post(monkeypatch):
    desired = _desired_apply()
    resource = {
        "drive_urls": {
            "Disk.Bay.0": "https://bmc.example.test/redfish/v1/Systems/System.Embedded.1/Storage/RAID.Integrated.1-1/Drives/Disk.Bay.0",
            "Disk.Bay.1": "https://bmc.example.test/redfish/v1/Systems/System.Embedded.1/Storage/RAID.Integrated.1-1/Drives/Disk.Bay.1",
        },
        "volume_urls": {},
    }
    calls = []
    monkeypatch.setattr(runtime, "_request_json", lambda method, url, *, credential, body=None: calls.append((method, url, body)) or {})
    runtime._apply_redfish(
        "storage.volume.apply",
        "https://bmc.example.test/redfish/v1/Systems/System.Embedded.1/Storage/RAID.Integrated.1-1/Volumes",
        resource,
        desired,
        {"username": "u", "password": "p", "ca_file": None},
    )
    assert calls == [(
        "POST",
        "https://bmc.example.test/redfish/v1/Systems/System.Embedded.1/Storage/RAID.Integrated.1-1/Volumes",
        {
            "Name": "os-mirror", "RAIDType": "RAID1",
            "Links": {"Drives": [
                {"@odata.id": resource["drive_urls"]["Disk.Bay.0"]},
                {"@odata.id": resource["drive_urls"]["Disk.Bay.1"]},
            ]},
        },
    )]


def test_storage_preview_rejects_swapped_or_ambiguous_physical_drive(monkeypatch):
    responses = _storage_responses()
    drive_url = "https://bmc.example.test/redfish/v1/Systems/System.Embedded.1/Storage/RAID.Integrated.1-1/Drives/Disk.Bay.0"
    responses[drive_url]["SerialNumber"] = ""
    calls: list[tuple[str, str, dict | None]] = []
    _patch_requests(monkeypatch, responses, calls)
    typed = _typed(_desired_apply(), "storage.volume.apply")
    with pytest.raises(HTTPException) as exc:
        runtime.preview({"parameters": {"typed_plan": typed}})
    assert exc.value.status_code == 409
    assert "stable SerialNumber" in str(exc.value.detail)


def test_storage_preview_rejects_existing_volume_name_with_different_raid(monkeypatch):
    existing = {
        "Id": "vol-os", "Name": "os-mirror", "RAIDType": "RAID0", "CapacityBytes": 100,
        "Links": {"Drives": [{"@odata.id": "/redfish/v1/Systems/System.Embedded.1/Storage/RAID.Integrated.1-1/Drives/Disk.Bay.0"}]},
        "Status": {"Health": "OK", "State": "Enabled"},
    }
    calls: list[tuple[str, str, dict | None]] = []
    _patch_requests(monkeypatch, _storage_responses(with_volume=existing), calls)
    typed = _typed(_desired_apply(), "storage.volume.apply")
    with pytest.raises(HTTPException) as exc:
        runtime.preview({"parameters": {"typed_plan": typed}})
    assert exc.value.status_code == 409
    assert "separate destructive ChangeSet" in str(exc.value.detail)


def test_storage_delete_requires_explicit_provider_capability_and_exact_confirmation():
    desired = {"controller_id": "RAID.Integrated.1-1", "volume_id": "vol-os", "confirm_volume_id": "wrong"}
    typed = _typed(desired, "storage.volume.delete")
    with pytest.raises(HTTPException) as exc:
        runtime._typed_plan({"parameters": {"typed_plan": typed}}) and runtime._load_runtime_context(typed)
    assert exc.value.status_code == 422
    assert "confirmation" in str(exc.value.detail)

    desired["confirm_volume_id"] = "vol-os"
    typed = _typed(desired, "storage.volume.delete", provider=_provider(allow_delete=False))
    with pytest.raises(HTTPException) as exc2:
        runtime._load_runtime_context(typed)
    assert exc2.value.status_code == 422
    assert "deletion is disabled" in str(exc2.value.detail)


def test_storage_delete_uses_exact_discovered_volume_url(monkeypatch):
    calls = []
    resource = {"drive_urls": {}, "volume_urls": {"vol-os": "https://bmc.example.test/redfish/v1/Systems/System.Embedded.1/Storage/RAID.Integrated.1-1/Volumes/vol-os"}}
    desired = {"controller_id": "RAID.Integrated.1-1", "volume_id": "vol-os", "confirm_volume_id": "vol-os"}
    monkeypatch.setattr(runtime, "_request_json", lambda method, url, *, credential, body=None: calls.append((method, url, body)) or {})
    runtime._apply_redfish("storage.volume.delete", "unused", resource, desired, {"username": "u", "password": "p", "ca_file": None})
    assert calls == [("DELETE", resource["volume_urls"]["vol-os"], None)]
    current = {"controller_id": "RAID.Integrated.1-1", "drives": [], "volumes": []}
    assert runtime._verification_matches("storage.volume.delete", current, desired) is True

def test_storage_preview_rejects_drive_already_bound_to_another_volume(monkeypatch):
    existing = {
        "Id": "vol-other", "Name": "data-mirror", "RAIDType": "RAID1", "CapacityBytes": 100,
        "Links": {"Drives": [{"@odata.id": "/redfish/v1/Systems/System.Embedded.1/Storage/RAID.Integrated.1-1/Drives/Disk.Bay.0"}]},
        "Status": {"Health": "OK", "State": "Enabled"},
    }
    calls: list[tuple[str, str, dict | None]] = []
    _patch_requests(monkeypatch, _storage_responses(with_volume=existing), calls)
    typed = _typed(_desired_apply(), "storage.volume.apply")
    with pytest.raises(HTTPException) as exc:
        runtime.preview({"parameters": {"typed_plan": typed}})
    assert exc.value.status_code == 409
    assert "already bound to another volume" in str(exc.value.detail)


def test_storage_preview_rejects_duplicate_stable_drive_serials(monkeypatch):
    responses = _storage_responses()
    controller = "https://bmc.example.test/redfish/v1/Systems/System.Embedded.1/Storage/RAID.Integrated.1-1"
    responses[controller + "/Drives/Disk.Bay.1"]["SerialNumber"] = "SERIAL-DISK-0"
    calls: list[tuple[str, str, dict | None]] = []
    _patch_requests(monkeypatch, responses, calls)
    typed = _typed(_desired_apply(), "storage.volume.apply")
    with pytest.raises(HTTPException) as exc:
        runtime.preview({"parameters": {"typed_plan": typed}})
    assert exc.value.status_code == 409
    assert "unique stable SerialNumber" in str(exc.value.detail)


def test_signed_storage_apply_execution_binds_preview_and_verifies(monkeypatch):
    desired = _desired_apply()
    before = {
        "controller_id": desired["controller_id"], "controller_name": "PERC H755N Front",
        "drives": [
            {"id": "Disk.Bay.0", "name": "NVMe 0", "serial_number": "SERIAL-0", "part_number": "PN", "model": "EXAMPLE", "media_type": "SSD", "protocol": "NVMe", "capacity_bytes": 1000, "health": "OK", "state": "Enabled"},
            {"id": "Disk.Bay.1", "name": "NVMe 1", "serial_number": "SERIAL-1", "part_number": "PN", "model": "EXAMPLE", "media_type": "SSD", "protocol": "NVMe", "capacity_bytes": 1000, "health": "OK", "state": "Enabled"},
        ],
        "volumes": [],
    }
    after = json.loads(json.dumps(before))
    after["volumes"] = [{
        "id": "vol-os", "name": desired["volume_name"], "raid_type": desired["raid_type"], "capacity_bytes": 1000,
        "drive_ids": desired["drive_ids"], "health": "OK", "state": "Enabled",
    }]
    preview = {
        "provider_kind": "redfish", "operation": "storage.volume.apply", "current": before,
        "current_hash": runtime.sha256_hex(before), "active_probe": True,
        "secret_output_suppressed": True, "credential_material_returned": False,
        "arbitrary_cli": False, "arbitrary_shell": False,
    }
    typed = _typed(desired, "storage.volume.apply", runtime_preview=preview)
    key = "execution-key-0123456789abcdef0123456789abcdef"
    ticket, signature = _signed_ticket(typed, key)
    monkeypatch.setattr(runtime, "EXECUTION_ENABLED", True)
    monkeypatch.setattr(runtime, "EXECUTION_KEY", key)
    monkeypatch.setattr(runtime, "VERIFY_ATTEMPTS", 1)
    monkeypatch.setattr(runtime, "_credential_profile", lambda ref: {"username": "hidden", "password": "hidden", "ca_file": None})
    resource = {
        "volumes_url": "https://bmc.example.test/redfish/v1/Systems/System.Embedded.1/Storage/RAID.Integrated.1-1/Volumes",
        "drive_urls": {
            "Disk.Bay.0": "https://bmc.example.test/redfish/v1/Drives/Disk.Bay.0",
            "Disk.Bay.1": "https://bmc.example.test/redfish/v1/Drives/Disk.Bay.1",
        },
        "volume_urls": {},
    }
    observations = iter([(resource["volumes_url"], resource, before), (resource["volumes_url"], resource, after)])
    seen_desired = []
    def fake_current(provider, credential, operation, desired_state=None):
        seen_desired.append(desired_state)
        return next(observations)
    monkeypatch.setattr(runtime, "_redfish_current", fake_current)
    applied = []
    monkeypatch.setattr(runtime, "_apply_redfish", lambda operation, url, resource_state, desired_state, credential: applied.append((operation, desired_state)))
    runtime._USED_TICKETS.clear()
    result = runtime.execute(ticket, signature)
    assert result["state"] == "SUCCEEDED"
    assert applied == [("storage.volume.apply", desired)]
    assert seen_desired == [desired, desired]
    assert result["verification"]["checks"][1]["status"] == "PASS"
    assert "hidden" not in json.dumps(result)
