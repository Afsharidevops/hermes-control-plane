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


def _provider_snapshot() -> dict:
    snapshot = {
        "id": "ipr_0123456789abcdef",
        "name": "bmc-a",
        "kind": "redfish",
        "endpoint": "https://bmc.example.test/redfish/v1",
        "credential_ref": "cred_redfish12345",
        "credential_snapshot": {"id": "cred_redfish12345", "kind": "generic", "status": "configured", "metadata": {}},
        "api_version": "1.20.0",
        "implementation_version": "redfish-http-v1",
        "site": "dc1",
        "zone": "rack-a",
        "capabilities": {"system_id": "System.Embedded.1", "manager_id": "iDRAC.Embedded.1", "virtual_media_id": "CD", "virtual_media_image_hosts": ["repo.example.test"], "bios_attribute_allowlist": ["BootMode", "SriovGlobalEnable"], "firmware_image_hosts": ["firmware.example.test"], "firmware_component_allowlist": ["BMC", "BIOS"]},
        "labels": {},
        "health_status": "HEALTHY",
        "status": "configured",
    }
    snapshot["snapshot_hash"] = runtime.sha256_hex(snapshot)
    return snapshot


def _system(
    power: str = "On", boot_target: str = "Hdd", boot_enabled: str = "Disabled",
    *, last_reset_time: str = "2026-08-21T12:00:00Z", boot_progress_time: str = "2026-08-21T12:00:05Z",
) -> dict:
    return {
        "Id": "System.Embedded.1",
        "Name": "PowerEdge",
        "Manufacturer": "Example",
        "Model": "R760",
        "SerialNumber": "SERIAL123",
        "PowerState": power,
        "LastResetTime": last_reset_time,
        "BootProgress": {"LastState": "OSRunning", "LastStateTime": boot_progress_time},
        "Status": {"Health": "OK", "State": "Enabled"},
        "Boot": {
            "BootSourceOverrideTarget": boot_target,
            "BootSourceOverrideEnabled": boot_enabled,
            "BootSourceOverrideMode": "UEFI",
        },
        "Actions": {"#ComputerSystem.Reset": {"target": "/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset"}},
        "Links": {"ManagedBy": [{"@odata.id": "/redfish/v1/Managers/iDRAC.Embedded.1"}]},
    }


def _typed(desired: dict, operation: str, runtime_preview: dict | None = None) -> dict:
    provider = _provider_snapshot()
    typed = {
        "schema_version": 5,
        "kind": "RedfishBareMetalPlan",
        "operation": operation,
        "provider": {
            "id": provider["id"],
            "kind": provider["kind"],
            "api_version": provider["api_version"],
            "implementation_version": provider["implementation_version"],
            "credential_ref": provider["credential_ref"],
            "snapshot_hash": provider["snapshot_hash"],
        },
        "targets": [provider],
        "desired_state": desired,
        "runtime_preview": runtime_preview,
    }
    typed["plan_hash"] = runtime.sha256_hex(typed)
    return typed


def _signed_ticket(typed: dict, key: str):
    plan = {"parameters": {"typed_plan": typed}}
    ticket = {
        "changeset_id": "chg_0123456789abcdef",
        "plan_hash": runtime.sha256_hex(plan),
        "plan": plan,
        "preconditions": {
            "operation_job_id": "opj_0123456789abcdef",
            "operation_plan_id": "opn_0123456789abcdef",
            "executor": "infrastructure-provider-worker",
            "typed_plan_hash": typed["plan_hash"],
            "policy_generation": 1,
        },
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + 120,
    }
    signature = hmac.new(key.encode(), _canonical(ticket).encode(), hashlib.sha256).hexdigest()
    return ticket, signature


def test_redfish_preview_is_active_secret_safe_and_deterministic(monkeypatch):
    system = _system()
    monkeypatch.setattr(runtime, "_credential_profile", lambda ref: {"username": "hidden", "password": "hidden", "ca_file": None})
    monkeypatch.setattr(runtime, "_redfish_system", lambda provider, credential: ("https://bmc.example.test/redfish/v1/Systems/System.Embedded.1", system))
    typed = _typed({"target": "pxe", "enabled": "once", "mode": "uefi"}, "boot.set")
    preview = runtime.preview({"parameters": {"typed_plan": typed}})
    assert preview["active_probe"] is True
    assert preview["secret_output_suppressed"] is True
    assert preview["credential_material_returned"] is False
    assert preview["arbitrary_cli"] is False
    assert preview["arbitrary_shell"] is False
    assert preview["current"]["serial_number"] == "SERIAL123"
    assert preview["diff"] == [
        {"field": "boot_target", "from": "Hdd", "to": "Pxe"},
        {"field": "boot_enabled", "from": "Disabled", "to": "Once"},
    ]
    assert "hidden" not in json.dumps(preview)


def test_redfish_execution_rejects_state_drift_before_mutation(monkeypatch):
    before = runtime._safe_system_snapshot(_system(power="On"))
    preview = {
        "provider_kind": "redfish", "operation": "power.set", "current": before,
        "current_hash": runtime.sha256_hex(before), "active_probe": True,
        "secret_output_suppressed": True, "credential_material_returned": False,
        "arbitrary_cli": False, "arbitrary_shell": False,
    }
    typed = _typed({"state": "force-off"}, "power.set", preview)
    key = "execution-key-0123456789abcdef0123456789abcdef"
    ticket, signature = _signed_ticket(typed, key)
    monkeypatch.setattr(runtime, "EXECUTION_ENABLED", True)
    monkeypatch.setattr(runtime, "EXECUTION_KEY", key)
    monkeypatch.setattr(runtime, "_credential_profile", lambda ref: {"username": "hidden", "password": "hidden", "ca_file": None})
    monkeypatch.setattr(runtime, "_redfish_system", lambda provider, credential: ("https://bmc/system", _system(power="Off")))
    called = []
    monkeypatch.setattr(runtime, "_apply_redfish", lambda *args, **kwargs: called.append(True))
    runtime._USED_TICKETS.clear()
    with pytest.raises(HTTPException) as exc:
        runtime.execute(ticket, signature)
    assert exc.value.status_code == 409
    assert "drifted" in str(exc.value.detail)
    assert called == []


def test_signed_redfish_power_execution_is_fixed_verified_and_one_time(monkeypatch):
    initial_system = _system(power="On")
    before = runtime._safe_system_snapshot(initial_system)
    preview = {
        "provider_kind": "redfish", "operation": "power.set", "current": before,
        "current_hash": runtime.sha256_hex(before), "active_probe": True,
        "secret_output_suppressed": True, "credential_material_returned": False,
        "arbitrary_cli": False, "arbitrary_shell": False,
    }
    typed = _typed({"state": "force-off"}, "power.set", preview)
    key = "execution-key-0123456789abcdef0123456789abcdef"
    ticket, signature = _signed_ticket(typed, key)
    monkeypatch.setattr(runtime, "EXECUTION_ENABLED", True)
    monkeypatch.setattr(runtime, "EXECUTION_KEY", key)
    monkeypatch.setattr(runtime, "VERIFY_ATTEMPTS", 1)
    monkeypatch.setattr(runtime, "_credential_profile", lambda ref: {"username": "hidden", "password": "hidden", "ca_file": None})
    observations = iter([initial_system, _system(power="Off")])
    monkeypatch.setattr(runtime, "_redfish_system", lambda provider, credential: ("https://bmc/system", next(observations)))
    applied = []
    monkeypatch.setattr(runtime, "_apply_redfish", lambda operation, url, system, desired, credential: applied.append((operation, desired)))
    runtime._USED_TICKETS.clear()
    result = runtime.execute(ticket, signature)
    assert applied == [("power.set", {"state": "force-off"})]
    assert result["state"] == "SUCCEEDED"
    assert result["verification"]["checks"][1]["status"] == "PASS"
    assert result["verification"]["evidence"]["arbitrary_cli"] is False
    assert result["verification"]["evidence"]["raw_credentials_returned"] is False
    with pytest.raises(HTTPException) as replay:
        runtime.execute(ticket, signature)
    assert replay.value.status_code == 409
    assert "already been used" in str(replay.value.detail)


def test_redfish_desired_state_rejects_arbitrary_fields():
    typed = _typed({"state": "on", "command": "rm -rf /"}, "power.set")
    with pytest.raises(HTTPException) as exc:
        runtime._validate_desired_state("redfish", "power.set", typed["desired_state"])
    assert exc.value.status_code == 422


def test_redfish_endpoint_and_links_fail_closed_by_default(monkeypatch):
    monkeypatch.setattr(runtime, "ALLOW_HTTP", False)
    with pytest.raises(HTTPException) as plain_http:
        runtime._endpoint({"endpoint": "http://bmc.example.test/redfish/v1"})
    assert plain_http.value.status_code == 422
    with pytest.raises(HTTPException) as embedded:
        runtime._endpoint({"endpoint": "https://user:pass@bmc.example.test/redfish/v1"})
    assert embedded.value.status_code == 422
    with pytest.raises(HTTPException) as cross_origin:
        runtime._same_origin_url("https://bmc.example.test/redfish/v1", "https://evil.example.test/redfish/v1/Systems/1")
    assert cross_origin.value.status_code == 502


def test_redfish_http_redirect_is_rejected_without_leaking_credentials(monkeypatch):
    class RedirectingOpener:
        def open(self, request, timeout):  # noqa: ANN001
            raise runtime.urllib.error.HTTPError(request.full_url, 302, "Found", {}, None)

    monkeypatch.setattr(runtime.urllib.request, "build_opener", lambda *handlers: RedirectingOpener())
    with pytest.raises(HTTPException) as exc:
        runtime._request_json(
            "GET", "http://bmc.example.test/redfish/v1",
            credential={"username": "sensitive-user", "password": "sensitive-password", "ca_file": None},
        )
    assert exc.value.status_code == 502
    assert "redirect rejected" in str(exc.value.detail)
    assert "sensitive" not in str(exc.value.detail)

def test_redfish_request_disables_ambient_proxy_inheritance(monkeypatch):
    captured = []

    class FailingOpener:
        def open(self, request, timeout):  # noqa: ANN001
            raise runtime.urllib.error.URLError("offline")

    def fake_build_opener(*handlers):
        captured.extend(handlers)
        return FailingOpener()

    monkeypatch.setattr(runtime.urllib.request, "build_opener", fake_build_opener)
    with pytest.raises(HTTPException):
        runtime._request_json(
            "GET", "https://bmc.example.test/redfish/v1",
            credential={"username": "user", "password": "password", "ca_file": None},
        )
    proxy_handlers = [handler for handler in captured if isinstance(handler, runtime.urllib.request.ProxyHandler)]
    assert len(proxy_handlers) == 1
    assert proxy_handlers[0].proxies == {}


def test_redfish_restart_requires_observable_reset_marker_change():
    before = runtime._safe_system_snapshot(_system())
    unchanged = runtime._safe_system_snapshot(_system())
    changed = runtime._safe_system_snapshot(_system(last_reset_time="2026-08-21T12:10:00Z"))
    assert runtime._verification_matches("power.set", unchanged, {"state": "restart"}, before=before) is False
    assert runtime._verification_matches("power.set", changed, {"state": "restart"}, before=before) is True


def _virtual_media(*, image: str = "", inserted: bool = False, write_protected: bool = True) -> dict:
    return {
        "Id": "CD",
        "Name": "Virtual CD",
        "MediaTypes": ["CD", "DVD"],
        "Inserted": inserted,
        "WriteProtected": write_protected,
        "Image": image or None,
        "ConnectedVia": "URI",
        "Actions": {
            "#VirtualMedia.InsertMedia": {"target": "/redfish/v1/Managers/iDRAC.Embedded.1/VirtualMedia/CD/Actions/VirtualMedia.InsertMedia"},
            "#VirtualMedia.EjectMedia": {"target": "/redfish/v1/Managers/iDRAC.Embedded.1/VirtualMedia/CD/Actions/VirtualMedia.EjectMedia"},
        },
    }


def test_redfish_virtual_media_preview_is_allowlisted_and_secret_safe(monkeypatch):
    media = _virtual_media()
    monkeypatch.setattr(runtime, "_credential_profile", lambda ref: {"username": "hidden", "password": "hidden", "ca_file": None})
    monkeypatch.setattr(
        runtime, "_redfish_current",
        lambda provider, credential, operation: ("https://bmc.example.test/redfish/v1/Managers/iDRAC.Embedded.1/VirtualMedia/CD", media, runtime._safe_virtual_media_snapshot(media)),
    )
    typed = _typed({"image_url": "https://repo.example.test/images/node.iso", "write_protected": True}, "virtual-media.insert")
    preview = runtime.preview({"parameters": {"typed_plan": typed}})
    assert preview["active_probe"] is True
    assert preview["current"]["image_present"] is False
    assert preview["diff"][0]["field"] == "image_sha256"
    assert preview["diff"][1:] == [
        {"field": "inserted", "from": False, "to": True},
    ]
    assert "hidden" not in json.dumps(preview)


def test_redfish_virtual_media_requires_exact_image_host_allowlist():
    provider = _provider_snapshot()
    with pytest.raises(HTTPException) as exc:
        runtime._virtual_media_image_allowed(provider, "https://untrusted.example.test/node.iso")
    assert exc.value.status_code == 422
    assert "allowlisted" in str(exc.value.detail)


def test_redfish_virtual_media_rejects_credential_or_query_bearing_image_url():
    for image_url in (
        "https://user:pass@repo.example.test/node.iso",
        "https://repo.example.test/node.iso?token=secret",
        "http://repo.example.test/node.iso",
    ):
        with pytest.raises(HTTPException) as exc:
            runtime._validate_desired_state("redfish", "virtual-media.insert", {"image_url": image_url})
        assert exc.value.status_code == 422


def test_redfish_virtual_media_insert_uses_fixed_action_and_write_protection(monkeypatch):
    media = _virtual_media()
    calls = []
    monkeypatch.setattr(
        runtime, "_request_json",
        lambda method, url, *, credential, body=None: calls.append((method, url, body)) or {},
    )
    runtime._apply_redfish(
        "virtual-media.insert",
        "https://bmc.example.test/redfish/v1/Managers/iDRAC.Embedded.1/VirtualMedia/CD",
        media,
        {"image_url": "https://repo.example.test/images/node.iso", "write_protected": True},
        {"username": "hidden", "password": "hidden", "ca_file": None},
    )
    assert calls == [(
        "POST",
        "https://bmc.example.test/redfish/v1/Managers/iDRAC.Embedded.1/VirtualMedia/CD/Actions/VirtualMedia.InsertMedia",
        {"Image": "https://repo.example.test/images/node.iso", "Inserted": True, "WriteProtected": True},
    )]


def test_redfish_virtual_media_snapshot_redacts_unsafe_current_image_reference():
    snapshot = runtime._safe_virtual_media_snapshot(
        _virtual_media(image="https://user:password@repo.example.test/node.iso?token=secret", inserted=True)
    )
    assert snapshot["image_present"] is True
    assert snapshot["image_url"] == ""
    assert len(snapshot["image_sha256"]) == 64
    assert "password" not in json.dumps(snapshot)
    assert "secret" not in json.dumps(snapshot)


def _bios(*, attrs: dict | None = None) -> dict:
    return {
        "Id": "Bios",
        "Name": "BIOS Configuration Current Settings",
        "Attributes": attrs or {"BootMode": "Uefi", "SriovGlobalEnable": "Disabled"},
        "@Redfish.Settings": {"SettingsObject": {"@odata.id": "/redfish/v1/Systems/System.Embedded.1/Bios/Settings"}},
    }


def test_redfish_bios_preview_is_bounded_and_deterministic(monkeypatch):
    current_bios = _bios()
    desired = {"attributes": {"BootMode": "Bios", "SriovGlobalEnable": "Enabled"}}
    monkeypatch.setattr(runtime, "_credential_profile", lambda ref: {"username": "hidden", "password": "hidden", "ca_file": None})
    monkeypatch.setattr(
        runtime,
        "_redfish_current",
        lambda provider, credential, operation, desired_state=None: (
            "https://bmc.example.test/redfish/v1/Systems/System.Embedded.1/Bios/Settings",
            current_bios,
            runtime._safe_bios_snapshot(current_bios, desired_state["attributes"]),
        ),
    )
    typed = _typed(desired, "bios.apply")
    preview = runtime.preview({"parameters": {"typed_plan": typed}})
    assert preview["active_probe"] is True
    assert preview["current"]["attributes"] == {"BootMode": "Uefi", "SriovGlobalEnable": "Disabled"}
    assert preview["diff"] == [
        {"field": "bios.BootMode", "from": "Uefi", "to": "Bios"},
        {"field": "bios.SriovGlobalEnable", "from": "Disabled", "to": "Enabled"},
    ]
    assert "hidden" not in json.dumps(preview)


def test_redfish_bios_apply_uses_fixed_attributes_patch(monkeypatch):
    calls = []
    monkeypatch.setattr(
        runtime,
        "_request_json",
        lambda method, url, *, credential, body=None: calls.append((method, url, body)) or {},
    )
    runtime._apply_redfish(
        "bios.apply",
        "https://bmc.example.test/redfish/v1/Systems/System.Embedded.1/Bios/Settings",
        _bios(),
        {"attributes": {"BootMode": "Bios", "SriovGlobalEnable": "Enabled"}},
        {"username": "hidden", "password": "hidden", "ca_file": None},
    )
    assert calls == [(
        "PATCH",
        "https://bmc.example.test/redfish/v1/Systems/System.Embedded.1/Bios/Settings",
        {"Attributes": {"BootMode": "Bios", "SriovGlobalEnable": "Enabled"}},
    )]


def test_redfish_bios_rejects_unbounded_or_structured_attributes():
    invalid = [
        {},
        {"attributes": {}},
        {"attributes": {"Unsafe Attribute": "value"}},
        {"attributes": {"BootMode": {"command": "arbitrary"}}},
        {"attributes": {"BootMode": "x\nunsafe"}},
    ]
    for desired in invalid:
        with pytest.raises(HTTPException) as exc:
            runtime._validate_desired_state("redfish", "bios.apply", desired)
        assert exc.value.status_code == 422


def test_redfish_bios_settings_object_must_stay_same_origin(monkeypatch):
    system = _system()
    system["Bios"] = {"@odata.id": "/redfish/v1/Systems/System.Embedded.1/Bios"}
    responses = {
        "https://bmc.example.test/redfish/v1/Systems/System.Embedded.1/Bios": {
            "Id": "Bios",
            "Attributes": {"BootMode": "Uefi"},
            "@Redfish.Settings": {"SettingsObject": {"@odata.id": "https://evil.example.test/Bios/Settings"}},
        }
    }
    monkeypatch.setattr(runtime, "_request_json", lambda method, url, *, credential, body=None: responses[url])
    with pytest.raises(HTTPException) as exc:
        runtime._redfish_bios(
            _provider_snapshot(),
            {"username": "hidden", "password": "hidden", "ca_file": None},
            "https://bmc.example.test/redfish/v1/Systems/System.Embedded.1",
            system,
        )
    assert exc.value.status_code == 502


def test_redfish_bios_verification_matches_only_requested_attributes():
    current = {"attributes": {"BootMode": "Bios", "SriovGlobalEnable": "Enabled"}}
    desired = {"attributes": {"BootMode": "Bios"}}
    assert runtime._verification_matches("bios.apply", current, desired) is True
    assert runtime._verification_matches("bios.apply", {"attributes": {"BootMode": "Uefi"}}, desired) is False


def test_signed_redfish_bios_execution_rejects_drift_and_verifies_pending_settings(monkeypatch):
    desired = {"attributes": {"BootMode": "Bios"}}
    before_resource = _bios(attrs={"BootMode": "Uefi"})
    before = runtime._safe_bios_snapshot(before_resource, desired["attributes"])
    preview = {
        "provider_kind": "redfish", "operation": "bios.apply", "current": before,
        "current_hash": runtime.sha256_hex(before), "active_probe": True,
        "secret_output_suppressed": True, "credential_material_returned": False,
        "arbitrary_cli": False, "arbitrary_shell": False,
    }
    typed = _typed(desired, "bios.apply", preview)
    key = "execution-key-0123456789abcdef0123456789abcdef"
    ticket, signature = _signed_ticket(typed, key)
    monkeypatch.setattr(runtime, "EXECUTION_ENABLED", True)
    monkeypatch.setattr(runtime, "EXECUTION_KEY", key)
    monkeypatch.setattr(runtime, "VERIFY_ATTEMPTS", 1)
    monkeypatch.setattr(runtime, "_credential_profile", lambda ref: {"username": "hidden", "password": "hidden", "ca_file": None})
    observations = iter([
        ("https://bmc.example.test/redfish/v1/Systems/System.Embedded.1/Bios/Settings", before_resource, before),
        (
            "https://bmc.example.test/redfish/v1/Systems/System.Embedded.1/Bios/Settings",
            _bios(attrs={"BootMode": "Bios"}),
            {"resource_id": "Bios", "name": "BIOS Configuration Current Settings", "attributes": {"BootMode": "Bios"}, "attribute_count": 1},
        ),
    ])
    monkeypatch.setattr(runtime, "_redfish_current", lambda provider, credential, operation, desired_state=None: next(observations))
    applied = []
    monkeypatch.setattr(runtime, "_apply_redfish", lambda operation, url, resource, desired_state, credential: applied.append((operation, url, desired_state)))
    runtime._USED_TICKETS.clear()
    result = runtime.execute(ticket, signature)
    assert result["state"] == "SUCCEEDED"
    assert applied == [(
        "bios.apply",
        "https://bmc.example.test/redfish/v1/Systems/System.Embedded.1/Bios/Settings",
        desired,
    )]
    assert result["verification"]["checks"][1]["status"] == "PASS"
    assert "hidden" not in json.dumps(result)


def test_redfish_bios_requires_provider_attribute_allowlist():
    provider = _provider_snapshot()
    provider["capabilities"]["bios_attribute_allowlist"] = ["BootMode"]
    with pytest.raises(HTTPException) as exc:
        runtime._bios_attributes_allowed(provider, {"SriovGlobalEnable": "Enabled"})
    assert exc.value.status_code == 422
    assert "allowlisted" in str(exc.value.detail)


def _firmware(*, component_id: str = "BMC", version: str = "6.10.30.00", updateable: bool = True) -> dict:
    return {
        "Id": component_id,
        "Name": "Integrated Remote Access Controller",
        "SoftwareId": "BMC-FW",
        "Version": version,
        "Updateable": updateable,
        "Status": {"Health": "OK", "State": "Enabled"},
    }


def test_redfish_firmware_desired_state_is_exact_and_credential_free():
    desired = runtime._validate_desired_state(
        "redfish",
        "firmware.apply",
        {
            "image_url": "https://firmware.example.test/redfish/idrac-7.00.bin",
            "component_id": "BMC",
            "expected_version": "7.00.00.00",
        },
    )
    assert desired == {
        "image_url": "https://firmware.example.test/redfish/idrac-7.00.bin",
        "component_id": "BMC",
        "expected_version": "7.00.00.00",
    }
    for invalid in (
        {"image_url": "https://user:secret@firmware.example.test/fw.bin", "component_id": "BMC", "expected_version": "7"},
        {"image_url": "https://firmware.example.test/fw.bin?token=secret", "component_id": "BMC", "expected_version": "7"},
        {"image_url": "http://firmware.example.test/fw.bin", "component_id": "BMC", "expected_version": "7"},
        {"image_url": "https://firmware.example.test/fw.bin", "component_id": "BMC; reboot", "expected_version": "7"},
        {"image_url": "https://firmware.example.test/fw.bin", "component_id": "BMC", "expected_version": "7\nunsafe"},
        {"image_url": "https://firmware.example.test/fw.bin", "component_id": "BMC", "expected_version": "7", "command": "raw"},
    ):
        with pytest.raises(HTTPException) as exc:
            runtime._validate_desired_state("redfish", "firmware.apply", invalid)
        assert exc.value.status_code == 422


def test_redfish_firmware_requires_exact_provider_allowlists():
    provider = _provider_snapshot()
    runtime._firmware_request_allowed(
        provider,
        {"image_url": "https://firmware.example.test/fw.bin", "component_id": "BMC", "expected_version": "7"},
    )
    with pytest.raises(HTTPException) as host:
        runtime._firmware_request_allowed(
            provider,
            {"image_url": "https://evil.example.test/fw.bin", "component_id": "BMC", "expected_version": "7"},
        )
    assert host.value.status_code == 422
    with pytest.raises(HTTPException) as component:
        runtime._firmware_request_allowed(
            provider,
            {"image_url": "https://firmware.example.test/fw.bin", "component_id": "NIC-1", "expected_version": "7"},
        )
    assert component.value.status_code == 422


def test_redfish_firmware_discovers_update_service_and_exact_component(monkeypatch):
    responses = {
        "https://bmc.example.test/redfish/v1": {"UpdateService": {"@odata.id": "/redfish/v1/UpdateService"}},
        "https://bmc.example.test/redfish/v1/UpdateService": {
            "ServiceEnabled": True,
            "FirmwareInventory": {"@odata.id": "/redfish/v1/UpdateService/FirmwareInventory"},
            "Actions": {"#UpdateService.SimpleUpdate": {"target": "/redfish/v1/UpdateService/Actions/UpdateService.SimpleUpdate"}},
        },
        "https://bmc.example.test/redfish/v1/UpdateService/FirmwareInventory": {
            "Members": [
                {"@odata.id": "/redfish/v1/UpdateService/FirmwareInventory/BMC"},
                {"@odata.id": "/redfish/v1/UpdateService/FirmwareInventory/BIOS"},
            ]
        },
        "https://bmc.example.test/redfish/v1/UpdateService/FirmwareInventory/BMC": _firmware(),
    }
    monkeypatch.setattr(runtime, "_request_json", lambda method, url, *, credential, body=None: responses[url])
    action_url, component_url, component = runtime._redfish_firmware(
        _provider_snapshot(), {"username": "hidden", "password": "hidden", "ca_file": None}, "BMC"
    )
    assert action_url == "https://bmc.example.test/redfish/v1/UpdateService/Actions/UpdateService.SimpleUpdate"
    assert component_url == "https://bmc.example.test/redfish/v1/UpdateService/FirmwareInventory/BMC"
    assert component["Version"] == "6.10.30.00"


def test_redfish_firmware_rejects_cross_origin_simple_update(monkeypatch):
    responses = {
        "https://bmc.example.test/redfish/v1": {"UpdateService": {"@odata.id": "/redfish/v1/UpdateService"}},
        "https://bmc.example.test/redfish/v1/UpdateService": {
            "ServiceEnabled": True,
            "FirmwareInventory": {"@odata.id": "/redfish/v1/UpdateService/FirmwareInventory"},
            "Actions": {"#UpdateService.SimpleUpdate": {"target": "https://evil.example.test/update"}},
        },
    }
    monkeypatch.setattr(runtime, "_request_json", lambda method, url, *, credential, body=None: responses[url])
    with pytest.raises(HTTPException) as exc:
        runtime._redfish_firmware(
            _provider_snapshot(), {"username": "hidden", "password": "hidden", "ca_file": None}, "BMC"
        )
    assert exc.value.status_code == 502


def test_redfish_firmware_apply_uses_fixed_simpleupdate_body(monkeypatch):
    calls = []
    monkeypatch.setattr(
        runtime,
        "_request_json",
        lambda method, url, *, credential, body=None: calls.append((method, url, body)) or {},
    )
    runtime._apply_redfish(
        "firmware.apply",
        "https://bmc.example.test/redfish/v1/UpdateService/Actions/UpdateService.SimpleUpdate",
        {"component_url": "https://bmc.example.test/redfish/v1/UpdateService/FirmwareInventory/BMC"},
        {
            "image_url": "https://firmware.example.test/redfish/idrac-7.00.bin",
            "component_id": "BMC",
            "expected_version": "7.00.00.00",
        },
        {"username": "hidden", "password": "hidden", "ca_file": None},
    )
    assert calls == [(
        "POST",
        "https://bmc.example.test/redfish/v1/UpdateService/Actions/UpdateService.SimpleUpdate",
        {
            "ImageURI": "https://firmware.example.test/redfish/idrac-7.00.bin",
            "Targets": ["https://bmc.example.test/redfish/v1/UpdateService/FirmwareInventory/BMC"],
        },
    )]


def test_redfish_firmware_preview_binds_current_version_without_image_secrets(monkeypatch):
    desired = {
        "image_url": "https://firmware.example.test/redfish/idrac-7.00.bin",
        "component_id": "BMC",
        "expected_version": "7.00.00.00",
    }
    current = runtime._safe_firmware_snapshot(_firmware())
    monkeypatch.setattr(runtime, "_credential_profile", lambda ref: {"username": "hidden", "password": "hidden", "ca_file": None})
    monkeypatch.setattr(
        runtime,
        "_redfish_current",
        lambda provider, credential, operation, desired_state=None: (
            "https://bmc.example.test/redfish/v1/UpdateService/Actions/UpdateService.SimpleUpdate",
            {"component_url": "https://bmc.example.test/redfish/v1/UpdateService/FirmwareInventory/BMC"},
            current,
        ),
    )
    preview = runtime.preview({"parameters": {"typed_plan": _typed(desired, "firmware.apply")}})
    assert preview["current"]["version"] == "6.10.30.00"
    assert preview["diff"] == [{"field": "firmware.BMC.version", "from": "6.10.30.00", "to": "7.00.00.00"}]
    assert "hidden" not in json.dumps(preview)


def test_signed_redfish_firmware_execution_verifies_exact_version_and_is_idempotent(monkeypatch):
    desired = {
        "image_url": "https://firmware.example.test/redfish/idrac-7.00.bin",
        "component_id": "BMC",
        "expected_version": "7.00.00.00",
    }
    before = runtime._safe_firmware_snapshot(_firmware(version="6.10.30.00"))
    after = runtime._safe_firmware_snapshot(_firmware(version="7.00.00.00"))
    preview = {
        "provider_kind": "redfish", "operation": "firmware.apply", "current": before,
        "current_hash": runtime.sha256_hex(before), "active_probe": True,
        "secret_output_suppressed": True, "credential_material_returned": False,
        "arbitrary_cli": False, "arbitrary_shell": False,
    }
    typed = _typed(desired, "firmware.apply", preview)
    key = "execution-key-0123456789abcdef0123456789abcdef"
    ticket, signature = _signed_ticket(typed, key)
    monkeypatch.setattr(runtime, "EXECUTION_ENABLED", True)
    monkeypatch.setattr(runtime, "EXECUTION_KEY", key)
    monkeypatch.setattr(runtime, "FIRMWARE_VERIFY_ATTEMPTS", 1)
    monkeypatch.setattr(runtime, "_credential_profile", lambda ref: {"username": "hidden", "password": "hidden", "ca_file": None})
    observations = iter([
        ("https://bmc.example.test/update", {"component_url": "https://bmc.example.test/fw/BMC"}, before),
        ("https://bmc.example.test/update", {"component_url": "https://bmc.example.test/fw/BMC"}, after),
    ])
    monkeypatch.setattr(runtime, "_redfish_current", lambda provider, credential, operation, desired_state=None: next(observations))
    applied = []
    monkeypatch.setattr(runtime, "_apply_redfish", lambda operation, url, resource, desired_state, credential: applied.append((operation, desired_state)))
    runtime._USED_TICKETS.clear()
    result = runtime.execute(ticket, signature)
    assert applied == [("firmware.apply", desired)]
    assert result["state"] == "SUCCEEDED"
    assert result["verification"]["evidence"]["mutation_applied"] is True
    assert result["verification"]["checks"][1]["status"] == "PASS"

    already = after
    preview2 = dict(preview, current=already, current_hash=runtime.sha256_hex(already))
    typed2 = _typed(desired, "firmware.apply", preview2)
    ticket2, signature2 = _signed_ticket(typed2, key)
    monkeypatch.setattr(
        runtime, "_redfish_current",
        lambda provider, credential, operation, desired_state=None: (
            "https://bmc.example.test/update", {"component_url": "https://bmc.example.test/fw/BMC"}, already
        ),
    )
    applied.clear()
    runtime._USED_TICKETS.clear()
    result2 = runtime.execute(ticket2, signature2)
    assert applied == []
    assert result2["state"] == "SUCCEEDED"
    assert result2["verification"]["evidence"]["mutation_applied"] is False


def _ipmi_provider_snapshot() -> dict:
    snapshot = {
        "id": "ipr_fedcba9876543210",
        "name": "legacy-bmc-a",
        "kind": "ipmi",
        "endpoint": "ipmi://192.0.2.45:623",
        "credential_ref": "cred_ipmi12345",
        "credential_snapshot": {"id": "cred_ipmi12345", "kind": "generic", "status": "configured", "metadata": {}},
        "api_version": "ipmi-2.0",
        "implementation_version": "ipmitool-lanplus-v1",
        "site": "dc1",
        "zone": "rack-a",
        "capabilities": {"transport": "lanplus", "fallback_only": True},
        "labels": {},
        "health_status": "HEALTHY",
        "status": "configured",
    }
    snapshot["snapshot_hash"] = runtime.sha256_hex(snapshot)
    return snapshot


def _ipmi_typed(desired: dict, operation: str, runtime_preview: dict | None = None) -> dict:
    provider = _ipmi_provider_snapshot()
    typed = {
        "schema_version": 5,
        "kind": "IPMIBareMetalPlan",
        "operation": operation,
        "provider": {
            "id": provider["id"],
            "kind": provider["kind"],
            "api_version": provider["api_version"],
            "implementation_version": provider["implementation_version"],
            "credential_ref": provider["credential_ref"],
            "snapshot_hash": provider["snapshot_hash"],
        },
        "targets": [provider],
        "desired_state": desired,
        "runtime_preview": runtime_preview,
    }
    typed["plan_hash"] = runtime.sha256_hex(typed)
    return typed


def test_ipmi_endpoint_and_desired_state_fail_closed():
    provider = _ipmi_provider_snapshot()
    assert runtime._ipmi_endpoint(provider) == ("192.0.2.45", 623)
    for endpoint in (
        "https://192.0.2.45",
        "ipmi://user:secret@192.0.2.45",
        "ipmi://192.0.2.45/path",
        "ipmi://192.0.2.45?password=secret",
    ):
        bad = dict(provider, endpoint=endpoint)
        with pytest.raises(HTTPException) as exc:
            runtime._ipmi_endpoint(bad)
        assert exc.value.status_code == 422
    with pytest.raises(HTTPException) as extra:
        runtime._validate_desired_state("ipmi", "power.set", {"state": "on", "command": "raw"})
    assert extra.value.status_code == 422
    for state in ("graceful-restart", "restart", "power-cycle"):
        with pytest.raises(HTTPException) as unsupported:
            runtime._validate_desired_state("ipmi", "power.set", {"state": state})
        assert unsupported.value.status_code == 422
    for desired in ({"target": "none", "enabled": "once"}, {"target": "pxe", "enabled": "disabled"}):
        with pytest.raises(HTTPException) as unsupported_boot:
            runtime._validate_desired_state("ipmi", "boot.set", desired)
        assert unsupported_boot.value.status_code == 422


def test_ipmitool_uses_fixed_argv_password_environment_and_no_shell(monkeypatch):
    provider = _ipmi_provider_snapshot()
    seen = {}

    class Completed:
        returncode = 0
        stdout = "Chassis Power is on\n"
        stderr = ""

    monkeypatch.setattr(runtime.shutil, "which", lambda name: "/usr/bin/ipmitool" if name == "ipmitool" else None)

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        seen["kwargs"] = kwargs
        return Completed()

    monkeypatch.setattr(runtime.subprocess, "run", fake_run)
    output = runtime._run_ipmitool(
        provider,
        {"username": "operator", "password": "super-secret-password"},
        ["chassis", "power", "status"],
    )
    assert output == "Chassis Power is on\n"
    assert seen["argv"] == [
        "/usr/bin/ipmitool", "-I", "lanplus", "-H", "192.0.2.45", "-U", "operator", "-E", "-p", "623",
        "chassis", "power", "status",
    ]
    assert "super-secret-password" not in " ".join(seen["argv"])
    assert seen["kwargs"]["env"]["IPMI_PASSWORD"] == "super-secret-password"
    assert seen["kwargs"]["shell"] is False
    assert seen["kwargs"]["stdin"] is runtime.subprocess.DEVNULL
    assert seen["kwargs"]["capture_output"] is True


def test_ipmi_preview_is_active_secret_safe_and_normalized(monkeypatch):
    monkeypatch.setattr(runtime, "_ipmi_credential_profile", lambda ref: {"username": "hidden", "password": "hidden"})
    monkeypatch.setattr(
        runtime,
        "_run_ipmitool",
        lambda provider, credential, args: "Chassis Power is on\n" if args[-1] == "status" else "",
    )
    typed = _ipmi_typed({"state": "force-off"}, "power.set")
    preview = runtime.preview({"parameters": {"typed_plan": typed}})
    assert preview["provider_kind"] == "ipmi"
    assert preview["current"]["power_state"] == "On"
    assert preview["diff"] == [{"field": "power_state", "from": "On", "to": "force-off"}]
    assert preview["arbitrary_cli"] is False
    assert preview["arbitrary_shell"] is False
    assert "hidden" not in json.dumps(preview)


def test_ipmi_boot_parser_and_fixed_apply(monkeypatch):
    output = """Boot parameter 5 is valid/unlocked
 Boot Flags :
   - Boot Flag Valid
   - Options apply to all future boots
   - EFI boot
   - Boot Device Selector : Force PXE
"""
    snapshot = runtime._parse_ipmi_boot(output)
    assert snapshot["boot_target"] == "Pxe"
    assert snapshot["boot_enabled"] == "Continuous"
    assert snapshot["boot_mode"] == "UEFI"
    calls = []
    monkeypatch.setattr(runtime, "_run_ipmitool", lambda provider, credential, args: calls.append(args) or "")
    runtime._apply_ipmi(
        "boot.set", _ipmi_provider_snapshot(), {"target": "pxe", "enabled": "continuous", "mode": "uefi"},
        {"username": "hidden", "password": "hidden"},
    )
    assert calls == [["chassis", "bootdev", "pxe", "options=persistent,efiboot"]]


def test_signed_ipmi_power_execution_rejects_drift_and_then_verifies(monkeypatch):
    before = runtime._parse_ipmi_power("Chassis Power is on\n")
    after = runtime._parse_ipmi_power("Chassis Power is off\n")
    preview = {
        "provider_kind": "ipmi", "operation": "power.set", "current": before,
        "current_hash": runtime.sha256_hex(before), "active_probe": True,
        "secret_output_suppressed": True, "credential_material_returned": False,
        "arbitrary_cli": False, "arbitrary_shell": False,
    }
    typed = _ipmi_typed({"state": "force-off"}, "power.set", preview)
    key = "execution-key-0123456789abcdef0123456789abcdef"
    ticket, signature = _signed_ticket(typed, key)
    monkeypatch.setattr(runtime, "EXECUTION_ENABLED", True)
    monkeypatch.setattr(runtime, "EXECUTION_KEY", key)
    monkeypatch.setattr(runtime, "VERIFY_ATTEMPTS", 1)
    monkeypatch.setattr(runtime, "_ipmi_credential_profile", lambda ref: {"username": "hidden", "password": "hidden"})
    drift = dict(before, power_state="Off")
    monkeypatch.setattr(runtime, "_ipmi_current", lambda provider, credential, operation: (provider["endpoint"], {}, drift))
    applied = []
    monkeypatch.setattr(runtime, "_apply_ipmi", lambda *args: applied.append(args))
    runtime._USED_TICKETS.clear()
    with pytest.raises(HTTPException) as exc:
        runtime.execute(ticket, signature)
    assert exc.value.status_code == 409
    assert applied == []

    ticket, signature = _signed_ticket(typed, key)
    observations = iter([
        (_ipmi_provider_snapshot()["endpoint"], {}, before),
        (_ipmi_provider_snapshot()["endpoint"], {}, after),
    ])
    monkeypatch.setattr(runtime, "_ipmi_current", lambda provider, credential, operation: next(observations))
    runtime._USED_TICKETS.clear()
    result = runtime.execute(ticket, signature)
    assert result["state"] == "SUCCEEDED"
    assert result["verification"]["checks"][1]["id"] == "ipmi-active-verify"
    assert result["verification"]["evidence"]["raw_credentials_returned"] is False
    assert applied and applied[0][0] == "power.set"
