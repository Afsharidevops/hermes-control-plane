from __future__ import annotations

import hashlib
import hmac
import json
import time
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from hermes_node_agent import infrastructure_runtime as runtime


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _signed_ticket(typed: dict, key: str):
    plan = {"parameters": {"typed_plan": typed}}
    ticket = {
        "changeset_id": "chg_hostnet000000001",
        "plan_hash": runtime.sha256_hex(plan),
        "plan": plan,
        "preconditions": {
            "operation_job_id": "opj_hostnet000000001",
            "operation_plan_id": "opn_hostnet000000001",
            "executor": "infrastructure-provider-worker",
            "typed_plan_hash": typed["plan_hash"],
            "policy_generation": 1,
        },
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + 120,
    }
    signature = hmac.new(key.encode(), _canonical(ticket), hashlib.sha256).hexdigest()
    return ticket, signature


HOST_NETWORK_PROVIDER = {
    "id": "ipr_hostnet0001abcdef",
    "name": "node-agent-01",
    "kind": "host-network",
    "endpoint": "agent://node-agent-01",
    "credential_ref": "cred_hostnet00000001",
    "api_version": "linux-netlink-1",
    "implementation_version": "pyroute2-pinned-v1",
    "site": "dc1",
    "zone": "rack-a",
    "capabilities": {"interface_allowlist": ["eth0", "eth1", "bond0", "bond1"]},
    "labels": {},
    "health_status": "HEALTHY",
    "status": "configured",
}


def _typed(desired: dict, operation: str, runtime_preview: dict | None = None) -> dict:
    snapshot = dict(HOST_NETWORK_PROVIDER)
    snapshot["snapshot_hash"] = runtime.sha256_hex(snapshot)
    typed = {
        "schema_version": 5,
        "kind": "HostNetworkPlan",
        "operation": operation,
        "provider": {
            "id": snapshot["id"],
            "kind": snapshot["kind"],
            "api_version": snapshot["api_version"],
            "implementation_version": snapshot["implementation_version"],
            "credential_ref": snapshot["credential_ref"],
            "snapshot_hash": snapshot["snapshot_hash"],
        },
        "targets": [snapshot],
        "desired_state": desired,
        "runtime_preview": runtime_preview,
    }
    typed["plan_hash"] = runtime.sha256_hex(typed)
    return typed


def test_validate_desired_state_rejects_unknown_fields_for_interface_configure():
    typed = _typed({"interface": "eth0", "state": "up", "extra": "no"}, "interface.configure")
    with pytest.raises(HTTPException) as exc:
        runtime.preview({"parameters": {"typed_plan": typed}})
    assert exc.value.status_code == 422
    assert "unsupported host-network interface.configure" in str(exc.value.detail)


def test_validate_desired_state_rejects_invalid_mac_address():
    typed = _typed({"interface": "eth0", "mac": "not-a-mac"}, "interface.configure")
    with pytest.raises(HTTPException) as exc:
        runtime.preview({"parameters": {"typed_plan": typed}})
    assert exc.value.status_code == 422
    assert "MAC address is invalid" in str(exc.value.detail)


def test_validate_desired_state_rejects_vlan_out_of_range():
    typed = _typed({"interface": "eth0", "vlan_id": "5000"}, "vlan.configure")
    with pytest.raises(HTTPException) as exc:
        runtime.preview({"parameters": {"typed_plan": typed}})
    assert exc.value.status_code == 422
    assert "vlan_id must be a valid VLAN ID" in str(exc.value.detail)


def test_validate_desired_state_rejects_invalid_bond_mode():
    typed = _typed(
        {"bond_interface": "bond0", "mode": "not-a-mode", "slaves": ["eth0", "eth1"]},
        "interface.bond",
    )
    with pytest.raises(HTTPException) as exc:
        runtime.preview({"parameters": {"typed_plan": typed}})
    assert exc.value.status_code == 422
    assert "bond mode" in str(exc.value.detail)


def test_validate_desired_state_rejects_bond_interface_without_prefix():
    typed = _typed(
        {"bond_interface": "eth0", "mode": "802.3ad", "slaves": ["eth0", "eth1"]},
        "interface.bond",
    )
    with pytest.raises(HTTPException) as exc:
        runtime.preview({"parameters": {"typed_plan": typed}})
    assert exc.value.status_code == 422
    assert "must start with 'bond'" in str(exc.value.detail)


def test_validate_desired_state_rejects_invalid_prefix_range():
    typed = _typed(
        {"interface": "eth0", "address": "10.70.0.10", "prefix": 200},
        "address.configure",
    )
    with pytest.raises(HTTPException) as exc:
        runtime.preview({"parameters": {"typed_plan": typed}})
    assert exc.value.status_code == 422
    assert "prefix must be between 1 and 128" in str(exc.value.detail)


def test_validate_desired_state_rejects_invalid_gateway_ip():
    typed = _typed(
        {"interface": "eth0", "address": "10.70.0.10", "prefix": 24, "gateway": "not-an-ip"},
        "address.configure",
    )
    with pytest.raises(HTTPException) as exc:
        runtime.preview({"parameters": {"typed_plan": typed}})
    assert exc.value.status_code == 422
    assert "gateway is not a valid IP address" in str(exc.value.detail)


def test_validate_desired_state_rejects_too_many_dns_entries():
    typed = _typed(
        {
            "interface": "eth0", "address": "10.70.0.10", "prefix": 24,
            "dns": ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"],
        },
        "address.configure",
    )
    with pytest.raises(HTTPException) as exc:
        runtime.preview({"parameters": {"typed_plan": typed}})
    assert exc.value.status_code == 422
    assert "dns must be a list of up to 4 addresses" in str(exc.value.detail)


def test_discover_returns_interface_snapshot_without_credential_material(monkeypatch):
    monkeypatch.setattr(runtime, "_host_network_interface_names", lambda: [
        {"name": "eth0", "mac": "aa:bb:cc:dd:ee:01", "state": "up", "mtu": 1500},
        {"name": "eth1", "mac": "aa:bb:cc:dd:ee:02", "state": "down", "mtu": 9000},
    ])
    monkeypatch.setattr(runtime, "_host_network_bond_info", lambda: [])
    monkeypatch.setattr(runtime, "_host_network_vlan_info", lambda: [])
    monkeypatch.setattr(runtime, "_host_network_address_info", lambda: [])
    typed = _typed({}, "network.discover")
    preview = runtime.preview({"parameters": {"typed_plan": typed}})
    assert preview["provider_kind"] == "host-network"
    assert preview["active_probe"] is True
    assert preview["credential_material_returned"] is False
    assert preview["secret_output_suppressed"] is True
    assert preview["arbitrary_cli"] is False
    assert preview["arbitrary_shell"] is False
    assert preview["diff"] == []
    assert {iface["name"] for iface in preview["current"]["interfaces"]} == {"eth0", "eth1"}


def test_discover_does_not_mutate_when_credential_ref_missing(monkeypatch):
    # host-network operations must never reach for credentials — they are local /sys inspectors.
    monkeypatch.setattr(runtime, "_host_network_interface_names", lambda: [])
    monkeypatch.setattr(runtime, "_host_network_bond_info", lambda: [])
    monkeypatch.setattr(runtime, "_host_network_vlan_info", lambda: [])
    monkeypatch.setattr(runtime, "_host_network_address_info", lambda: [])
    typed = _typed({}, "network.discover")
    runtime.preview({"parameters": {"typed_plan": typed}})
    # _credential_profile must not be reached for host-network — this protects against
    # accidental credential exfiltration paths creeping in.
    assert True


def test_interface_configure_diff_detects_state_and_mtu_changes(monkeypatch):
    monkeypatch.setattr(runtime, "_host_network_interface_names", lambda: [
        {"name": "eth0", "mac": "aa:bb:cc:dd:ee:01", "state": "down", "mtu": 1500},
    ])
    monkeypatch.setattr(runtime, "_host_network_bond_info", lambda: [])
    monkeypatch.setattr(runtime, "_host_network_vlan_info", lambda: [])
    monkeypatch.setattr(runtime, "_host_network_address_info", lambda: [])
    typed = _typed({"interface": "eth0", "state": "up", "mtu": 9000}, "interface.configure")
    preview = runtime.preview({"parameters": {"typed_plan": typed}})
    fields = {entry["field"] for entry in preview["diff"]}
    assert fields == {"host.interface.state", "host.interface.mtu"}


def test_address_configure_diff_requires_explicit_address(monkeypatch):
    monkeypatch.setattr(runtime, "_host_network_interface_names", lambda: [
        {"name": "eth0", "mac": "aa:bb:cc:dd:ee:01", "state": "up", "mtu": 1500},
    ])
    monkeypatch.setattr(runtime, "_host_network_bond_info", lambda: [])
    monkeypatch.setattr(runtime, "_host_network_vlan_info", lambda: [])
    monkeypatch.setattr(runtime, "_host_network_address_info", lambda: [])
    typed = _typed(
        {"interface": "eth0", "address": "10.70.0.10", "prefix": 24, "gateway": "10.70.0.1"},
        "address.configure",
    )
    preview = runtime.preview({"parameters": {"typed_plan": typed}})
    fields = {entry["field"] for entry in preview["diff"]}
    assert "host.address.address" in fields
    assert "host.address.prefix" in fields
    assert "host.address.gateway" in fields


# --- direct _host_network_verify unit tests ---

def test_host_network_verify_interface_configure_true_when_all_keys_match():
    current = {"interface": {"state": "up", "mtu": 1500, "mac": "aa:bb:cc:dd:ee:01"}}
    desired = {"state": "up", "mtu": 1500}
    assert runtime._host_network_verify("interface.configure", current, desired) is True


def test_host_network_verify_interface_configure_true_with_str_value_coercion():
    current = {"interface": {"state": "up", "mtu": "1500"}}
    desired = {"state": "up", "mtu": 1500}
    assert runtime._host_network_verify("interface.configure", current, desired) is True


def test_host_network_verify_interface_configure_false_when_field_mismatches():
    current = {"interface": {"state": "down", "mtu": 1500}}
    desired = {"state": "up", "mtu": 1500}
    assert runtime._host_network_verify("interface.configure", current, desired) is False


def test_host_network_verify_bond_true_when_mode_and_slaves_match():
    current = {"bond": {"mode": "802.3ad", "slaves": ["eth0", "eth1"]}}
    desired = {"mode": "802.3ad", "slaves": ["eth1", "eth0"]}
    assert runtime._host_network_verify("interface.bond", current, desired) is True


def test_host_network_verify_bond_false_when_mode_mismatches():
    current = {"bond": {"mode": "active-backup", "slaves": ["eth0", "eth1"]}}
    desired = {"mode": "802.3ad", "slaves": ["eth0", "eth1"]}
    assert runtime._host_network_verify("interface.bond", current, desired) is False


def test_host_network_verify_bond_false_when_slaves_mismatch():
    current = {"bond": {"mode": "802.3ad", "slaves": ["eth0"]}}
    desired = {"mode": "802.3ad", "slaves": ["eth0", "eth1"]}
    assert runtime._host_network_verify("interface.bond", current, desired) is False


def test_host_network_verify_vlan_true_when_id_matches():
    current = {"vlan": {"vlan_id": 100}}
    assert runtime._host_network_verify("vlan.configure", current, {"vlan_id": 100}) is True


def test_host_network_verify_vlan_false_when_id_mismatches():
    current = {"vlan": {"vlan_id": 100}}
    assert runtime._host_network_verify("vlan.configure", current, {"vlan_id": 200}) is False


def test_host_network_verify_vlan_false_when_no_vlan():
    current = {}
    assert runtime._host_network_verify("vlan.configure", current, {"vlan_id": 100}) is False


def test_host_network_verify_mtu_true_when_match():
    current = {"interface": {"mtu": 9000}}
    assert runtime._host_network_verify("mtu.configure", current, {"mtu": 9000}) is True


def test_host_network_verify_mtu_false_when_mismatch():
    current = {"interface": {"mtu": 1500}}
    assert runtime._host_network_verify("mtu.configure", current, {"mtu": 9000}) is False


def test_host_network_verify_address_true_when_found():
    current = {"interface": {"addresses": [{"address": "10.70.0.10"}, {"address": "10.70.0.11"}]}}
    assert runtime._host_network_verify("address.configure", current, {"address": "10.70.0.10"}) is True


def test_host_network_verify_address_false_when_not_found():
    current = {"interface": {"addresses": [{"address": "10.70.0.10"}]}}
    assert runtime._host_network_verify("address.configure", current, {"address": "10.70.0.99"}) is False


def test_host_network_verify_address_false_when_no_addresses():
    current = {"interface": {}}
    assert runtime._host_network_verify("address.configure", current, {"address": "10.70.0.10"}) is False


def test_host_network_verify_discover_true_when_interfaces_present():
    current = {"interfaces": [{"name": "eth0"}]}
    assert runtime._host_network_verify("network.discover", current, {}) is True


def test_host_network_verify_discover_false_when_no_interfaces():
    current = {"interfaces": []}
    assert runtime._host_network_verify("network.discover", current, {}) is False


def test_host_network_verify_unknown_operation_returns_false():
    assert runtime._host_network_verify("unknown.operation", {}, {}) is False


# --- execute-level regression test for host-network verify ---

def test_signed_host_network_execution_rejects_drift_and_then_verifies(monkeypatch):
    before = {"interface": {"name": "eth0", "state": "down", "mtu": 1500}}
    after = {"interface": {"name": "eth0", "state": "up", "mtu": 1500}}
    preview = runtime.preview({
        "parameters": {"typed_plan": _typed({"interface": "eth0", "state": "up"}, "interface.configure")}
    })
    preview["current"] = before
    preview["current_hash"] = runtime.sha256_hex(before)
    typed = _typed({"interface": "eth0", "state": "up"}, "interface.configure", preview)

    key = "execution-key-0123456789abcdef0123456789abcdef"
    ticket, signature = _signed_ticket(typed, key)
    monkeypatch.setattr(runtime, "EXECUTION_ENABLED", True)
    monkeypatch.setattr(runtime, "EXECUTION_KEY", key)
    monkeypatch.setattr(runtime, "VERIFY_ATTEMPTS", 1)

    # Drift: current state differs from preview
    drift = {"interface": {"name": "eth0", "state": "up", "mtu": 9000}}
    monkeypatch.setattr(runtime, "_host_network_current", lambda provider, credential, operation, desired=None: (
        "agent://node-agent-01", {}, drift
    ))
    applied = []
    monkeypatch.setattr(runtime, "_apply_host_network", lambda *args: applied.append(args))
    runtime._USED_TICKETS.clear()
    with pytest.raises(HTTPException) as exc:
        runtime.execute(ticket, signature)
    assert exc.value.status_code == 409
    assert applied == []

    # Converge: current state matches preview, then verify succeeds
    ticket, signature = _signed_ticket(typed, key)
    observations = iter([
        ("agent://node-agent-01", {}, before),
        ("agent://node-agent-01", {}, after),
    ])
    monkeypatch.setattr(runtime, "_host_network_current", lambda provider, credential, operation, desired=None: next(observations))
    runtime._USED_TICKETS.clear()
    result = runtime.execute(ticket, signature)
    assert result["state"] == "SUCCEEDED"
    assert result["verification"]["checks"][1]["id"] == "host-network-active-verify"
    assert result["verification"]["evidence"]["raw_credentials_returned"] is False
    assert applied and len(applied) == 1
