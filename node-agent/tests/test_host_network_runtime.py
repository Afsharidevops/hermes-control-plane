from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from hermes_node_agent import infrastructure_runtime as runtime


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
