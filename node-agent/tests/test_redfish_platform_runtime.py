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


def _provider() -> dict:
    snapshot = {
        "id": "ipr_platform012345", "name": "rack-a-platform", "kind": "redfish",
        "endpoint": "https://bmc.example.test/redfish/v1", "credential_ref": "cred_platform12345",
        "credential_snapshot": {"id": "cred_platform12345", "kind": "generic", "status": "configured", "metadata": {}},
        "api_version": "1.20.0", "implementation_version": "redfish-http-v1", "site": "dc1", "zone": "rack-a",
        "capabilities": {
            "system_id": "System.Embedded.1",
            "bios_attribute_allowlist": ["SriovGlobalEnable", "IommuSupport"],
            "secure_boot": {"activation": "reboot", "reset_type": "GracefulRestart"},
            "hardware_feature_map": {
                "sriov": {"attribute": "SriovGlobalEnable", "enabled_value": "Enabled", "disabled_value": "Disabled", "activation": "reboot", "reset_type": "GracefulRestart"},
                "iommu": {"attribute": "IommuSupport", "enabled_value": "Enabled", "disabled_value": "Disabled", "activation": "reboot", "reset_type": "GracefulRestart"},
            },
            "boot_order": {"allowlist": ["Boot0001", "Boot0002", "Boot0003"], "activation": "reboot", "reset_type": "GracefulRestart"},
        },
        "labels": {}, "health_status": "HEALTHY", "status": "configured",
    }
    snapshot["snapshot_hash"] = runtime.sha256_hex(snapshot)
    return snapshot


def _typed(desired: dict, operation: str, runtime_preview: dict | None = None) -> dict:
    provider = _provider()
    typed = {
        "schema_version": 5, "kind": "RedfishBareMetalPlan", "operation": operation,
        "provider": {
            "id": provider["id"], "kind": provider["kind"], "api_version": provider["api_version"],
            "implementation_version": provider["implementation_version"], "credential_ref": provider["credential_ref"],
            "snapshot_hash": provider["snapshot_hash"],
        },
        "targets": [provider], "desired_state": desired, "runtime_preview": runtime_preview,
    }
    typed["plan_hash"] = runtime.sha256_hex(typed)
    return typed


def _signed_ticket(typed: dict, key: str):
    plan = {"parameters": {"typed_plan": typed}}
    ticket = {
        "changeset_id": "chg_platform012345", "plan_hash": runtime.sha256_hex(plan), "plan": plan,
        "preconditions": {
            "operation_job_id": "opj_platform012345", "operation_plan_id": "opn_platform012345",
            "executor": "infrastructure-provider-worker", "typed_plan_hash": typed["plan_hash"], "policy_generation": 1,
        },
        "issued_at": int(time.time()), "expires_at": int(time.time()) + 120,
    }
    signature = hmac.new(key.encode(), _canonical(ticket).encode(), hashlib.sha256).hexdigest()
    return ticket, signature


def _system(*, boot_order=None, last_reset="2026-08-21T12:00:00Z") -> dict:
    return {
        "Id": "System.Embedded.1", "PowerState": "On", "LastResetTime": last_reset,
        "BootProgress": {"LastState": "OSRunning", "LastStateTime": last_reset},
        "Boot": {
            "BootOrder": boot_order or ["Boot0002", "Boot0001"], "BootOrderPropertySelection": "BootOrder",
            "BootOptions": {"@odata.id": "/redfish/v1/Systems/System.Embedded.1/BootOptions"},
        },
        "Bios": {"@odata.id": "/redfish/v1/Systems/System.Embedded.1/Bios"},
        "SecureBoot": {"@odata.id": "/redfish/v1/Systems/System.Embedded.1/SecureBoot"},
        "Actions": {"#ComputerSystem.Reset": {"target": "/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset"}},
    }


def test_secure_boot_requires_reboot_and_active_current_boot_state():
    with pytest.raises(HTTPException) as exc:
        runtime._validate_desired_state("redfish", "secure-boot.apply", {"enabled": True, "activation": "immediate"})
    assert exc.value.status_code == 422
    assert "activation must be reboot" in str(exc.value.detail)

    current = runtime._safe_secure_boot_snapshot(
        _system(), {"SecureBootEnable": True, "SecureBootCurrentBoot": "Enabled", "SecureBootMode": "UserMode"}
    )
    assert current["enabled"] is True
    assert current["active_enabled"] is True
    assert runtime._verification_matches("secure-boot.apply", current, {"enabled": True, "activation": "reboot"}) is True


def test_secure_boot_apply_is_fixed_patch_plus_provider_declared_reset(monkeypatch):
    system_url = "https://bmc.example.test/redfish/v1/Systems/System.Embedded.1"
    secure_url = system_url + "/SecureBoot"
    system = _system()
    calls = []
    monkeypatch.setattr(runtime, "_request_json", lambda method, url, *, credential, body=None: calls.append((method, url, body)) or {})
    runtime._apply_redfish(
        "secure-boot.apply", secure_url,
        {"system_url": system_url, "system": system, "reset_type": "GracefulRestart"},
        {"enabled": True, "activation": "reboot"}, {"username": "u", "password": "p", "ca_file": None},
    )
    assert calls == [
        ("PATCH", secure_url, {"SecureBootEnable": True}),
        ("POST", system_url + "/Actions/ComputerSystem.Reset", {"ResetType": "GracefulRestart"}),
    ]


def test_feature_policy_is_exact_bios_mapping_and_apply_uses_no_arbitrary_surface(monkeypatch):
    provider = _provider()
    desired = {"enabled": True, "activation": "reboot"}
    policy = runtime._hardware_feature_policy(provider, "sriov.apply", desired)
    assert policy["attribute"] == "SriovGlobalEnable"
    assert policy["target_value"] == "Enabled"

    calls = []
    system_url = "https://bmc.example.test/redfish/v1/Systems/System.Embedded.1"
    settings_url = system_url + "/Bios/Settings"
    monkeypatch.setattr(runtime, "_request_json", lambda method, url, *, credential, body=None: calls.append((method, url, body)) or {})
    runtime._apply_redfish(
        "sriov.apply", settings_url,
        {
            "system_url": system_url, "system": _system(), "settings_url": settings_url,
            "attribute": "SriovGlobalEnable", "target_value": "Enabled",
            "activation": "reboot", "reset_type": "GracefulRestart",
        },
        desired, {"username": "u", "password": "p", "ca_file": None},
    )
    assert calls[0] == ("PATCH", settings_url, {"Attributes": {"SriovGlobalEnable": "Enabled"}})
    assert calls[1][0:2] == ("POST", system_url + "/Actions/ComputerSystem.Reset")


def test_feature_snapshot_rejects_unmapped_firmware_value():
    with pytest.raises(HTTPException) as exc:
        runtime._safe_feature_snapshot(
            _system(), {"Attributes": {"IommuSupport": "VendorMystery"}}, {"Attributes": {}},
            "IommuSupport", "Enabled", "Disabled",
        )
    assert exc.value.status_code == 409
    assert "unmapped active value" in str(exc.value.detail)


def test_boot_order_requires_enabled_present_allowlisted_boot_options(monkeypatch):
    provider = _provider()
    desired = {"order": ["Boot0001", "Boot0002"], "activation": "reboot"}
    system = _system()
    monkeypatch.setattr(runtime, "_redfish_system", lambda provider, credential: ("https://bmc.example.test/redfish/v1/Systems/System.Embedded.1", system))
    monkeypatch.setattr(runtime, "_redfish_boot_options", lambda system_url, system, credential: [
        {"reference": "Boot0001", "enabled": True, "display_name": "NVMe"},
        {"reference": "Boot0002", "enabled": False, "display_name": "PXE"},
    ])
    with pytest.raises(HTTPException) as exc:
        runtime._redfish_current(provider, {"username": "u", "password": "p", "ca_file": None}, "boot-order.apply", desired)
    assert exc.value.status_code == 409
    assert "disabled" in str(exc.value.detail)


def test_boot_order_apply_patches_only_persistent_order_then_reset(monkeypatch):
    system_url = "https://bmc.example.test/redfish/v1/Systems/System.Embedded.1"
    settings_url = system_url + "/Settings"
    calls = []
    monkeypatch.setattr(runtime, "_request_json", lambda method, url, *, credential, body=None: calls.append((method, url, body)) or {})
    desired = {"order": ["Boot0001", "Boot0002"], "activation": "reboot"}
    runtime._apply_redfish(
        "boot-order.apply", settings_url,
        {"system_url": system_url, "system": _system(), "settings_url": settings_url, "activation": "reboot", "reset_type": "GracefulRestart"},
        desired, {"username": "u", "password": "p", "ca_file": None},
    )
    assert calls == [
        ("PATCH", settings_url, {"Boot": {"BootOrder": ["Boot0001", "Boot0002"]}}),
        ("POST", system_url + "/Actions/ComputerSystem.Reset", {"ResetType": "GracefulRestart"}),
    ]


def test_signed_sriov_execution_binds_preview_and_verifies_active_state(monkeypatch):
    desired = {"enabled": True, "activation": "reboot"}
    before = {
        "attribute": "SriovGlobalEnable", "active_value": "Disabled", "pending_value": "Disabled",
        "enabled": False, "pending_enabled": False, "last_reset_time": "before", "boot_progress_time": "before",
    }
    after = {
        "attribute": "SriovGlobalEnable", "active_value": "Enabled", "pending_value": "Enabled",
        "enabled": True, "pending_enabled": True, "last_reset_time": "after", "boot_progress_time": "after",
    }
    preview = {
        "provider_kind": "redfish", "operation": "sriov.apply", "current": before,
        "current_hash": runtime.sha256_hex(before), "active_probe": True,
        "secret_output_suppressed": True, "credential_material_returned": False,
        "arbitrary_cli": False, "arbitrary_shell": False,
    }
    typed = _typed(desired, "sriov.apply", preview)
    key = "execution-key-0123456789abcdef0123456789abcdef"
    ticket, signature = _signed_ticket(typed, key)
    monkeypatch.setattr(runtime, "EXECUTION_ENABLED", True)
    monkeypatch.setattr(runtime, "EXECUTION_KEY", key)
    monkeypatch.setattr(runtime, "PLATFORM_VERIFY_ATTEMPTS", 1)
    monkeypatch.setattr(runtime, "PLATFORM_VERIFY_DELAY_SECONDS", 0)
    monkeypatch.setattr(runtime, "_credential_profile", lambda ref: {"username": "hidden", "password": "hidden", "ca_file": None})
    observations = iter([
        ("https://bmc/settings", {"settings_url": "https://bmc/settings"}, before),
        ("https://bmc/settings", {"settings_url": "https://bmc/settings"}, after),
    ])
    seen_desired = []

    def fake_current(provider, credential, operation, desired_state=None):
        seen_desired.append(desired_state)
        return next(observations)

    monkeypatch.setattr(runtime, "_redfish_current", fake_current)
    applied = []
    monkeypatch.setattr(runtime, "_apply_redfish", lambda operation, url, resource, desired_state, credential: applied.append((operation, desired_state)))
    runtime._USED_TICKETS.clear()
    result = runtime.execute(ticket, signature)
    assert result["state"] == "SUCCEEDED"
    assert applied == [("sriov.apply", desired)]
    assert seen_desired == [desired, desired]
    assert result["verification"]["checks"][1]["status"] == "PASS"
    assert "hidden" not in json.dumps(result)


def test_reboot_verification_tolerates_transient_bmc_unavailability(monkeypatch):
    desired = {"enabled": True, "activation": "reboot"}
    before = {
        "attribute": "IommuSupport", "active_value": "Disabled", "pending_value": "Disabled",
        "enabled": False, "pending_enabled": False, "last_reset_time": "before", "boot_progress_time": "before",
    }
    after = dict(before, active_value="Enabled", pending_value="Enabled", enabled=True, pending_enabled=True, last_reset_time="after", boot_progress_time="after")
    preview = {
        "provider_kind": "redfish", "operation": "iommu.apply", "current": before,
        "current_hash": runtime.sha256_hex(before), "active_probe": True,
        "secret_output_suppressed": True, "credential_material_returned": False,
        "arbitrary_cli": False, "arbitrary_shell": False,
    }
    typed = _typed(desired, "iommu.apply", preview)
    key = "execution-key-0123456789abcdef0123456789abcdef"
    ticket, signature = _signed_ticket(typed, key)
    monkeypatch.setattr(runtime, "EXECUTION_ENABLED", True)
    monkeypatch.setattr(runtime, "EXECUTION_KEY", key)
    monkeypatch.setattr(runtime, "PLATFORM_VERIFY_ATTEMPTS", 2)
    monkeypatch.setattr(runtime, "PLATFORM_VERIFY_DELAY_SECONDS", 0)
    monkeypatch.setattr(runtime, "_credential_profile", lambda ref: {"username": "hidden", "password": "hidden", "ca_file": None})
    calls = {"n": 0}

    def fake_current(provider, credential, operation, desired_state=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return "https://bmc/settings", {}, before
        if calls["n"] == 2:
            raise HTTPException(502, "provider request failed")
        return "https://bmc/settings", {}, after

    monkeypatch.setattr(runtime, "_redfish_current", fake_current)
    monkeypatch.setattr(runtime, "_apply_redfish", lambda *args, **kwargs: None)
    runtime._USED_TICKETS.clear()
    result = runtime.execute(ticket, signature)
    assert result["state"] == "SUCCEEDED"
    assert result["verification"]["evidence"]["last_probe_error"] == ""
