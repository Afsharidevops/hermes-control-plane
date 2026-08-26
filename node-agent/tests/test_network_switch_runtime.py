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


SWITCH_PROVIDER = {
    "id": "ipr_switch0001abcdef",
    "name": "leaf-switch-01",
    "kind": "network-switch",
    "endpoint": "https://198.51.100.10/restconf/data",
    "credential_ref": "cred_switch000000001",
    "api_version": runtime.SWITCH_RESTCONF_API_VERSION,
    "implementation_version": runtime.SWITCH_RESTCONF_IMPLEMENTATION_VERSION,
    "site": "dc1",
    "zone": "rack-a",
    "capabilities": {
        "profile": runtime.SWITCH_RESTCONF_PROFILE,
        "model": "ExampleSwitch-48P",
        "port_allowlist": ["Ethernet1", "Ethernet2"],
        "vlan_allowlist": [100, 200],
        "port_modes": {"Ethernet1": ["access"], "Ethernet2": ["trunk"]},
    },
    "labels": {},
    "health_status": "HEALTHY",
    "status": "configured",
}

CREDENTIAL = {"username": "switch-worker", "password": "s3cret-pass", "ca_file": None}


def _typed(desired: dict, operation: str, runtime_preview: dict | None = None) -> dict:
    snapshot = dict(SWITCH_PROVIDER)
    snapshot["snapshot_hash"] = runtime.sha256_hex(snapshot)
    typed = {
        "schema_version": 5,
        "kind": "NetworkSwitchPlan",
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


def _signed_ticket(typed: dict, key: str):
    plan = {"parameters": {"typed_plan": typed}}
    ticket = {
        "changeset_id": "chg_switch000000001",
        "plan_hash": runtime.sha256_hex(plan),
        "plan": plan,
        "preconditions": {
            "operation_job_id": "opj_switch000000001",
            "operation_plan_id": "opn_switch000000001",
            "executor": "infrastructure-provider-worker",
            "typed_plan_hash": typed["plan_hash"],
            "policy_generation": 1,
        },
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + 120,
    }
    signature = hmac.new(key.encode(), _canonical(ticket).encode(), hashlib.sha256).hexdigest()
    return ticket, signature


# --- runtime operation gate: only the three implemented operations are dispatchable ---

def test_deferred_switch_operations_remain_contract_only():
    for operation in ("bond.ensure", "network.attach", "network.detach", "bgp.configure"):
        typed = _typed({}, operation)
        with pytest.raises(HTTPException) as exc:
            runtime.preview({"parameters": {"typed_plan": typed}})
        assert exc.value.status_code == 422
        assert "not supported by trusted network-switch runtime" in str(exc.value.detail)


def test_execute_rejects_deferred_switch_operations(monkeypatch):
    monkeypatch.setattr(runtime, "EXECUTION_ENABLED", True)
    monkeypatch.setattr(runtime, "EXECUTION_KEY", "execution-key-0123456789abcdef0123456789abcdef")
    typed = _typed({}, "bgp.configure")
    ticket, signature = _signed_ticket(typed, "execution-key-0123456789abcdef0123456789abcdef")
    runtime._USED_TICKETS.clear()
    with pytest.raises(HTTPException) as exc:
        runtime.execute(ticket, signature)
    assert exc.value.status_code == 422


# --- closed desired-state schemas ---

def test_lldp_observe_rejects_desired_state_fields():
    with pytest.raises(HTTPException) as exc:
        runtime._validate_desired_state("network-switch", "lldp.observe", {"port": "Ethernet1"})
    assert exc.value.status_code == 422
    assert "does not accept desired_state fields" in str(exc.value.detail)


def test_vlan_ensure_requires_only_vlan_id_and_name():
    with pytest.raises(HTTPException) as exc:
        runtime._validate_desired_state("network-switch", "vlan.ensure", {"vlan_id": 100, "name": "prod", "extra": 1})
    assert exc.value.status_code == 422
    assert "requires only vlan_id and name" in str(exc.value.detail)


def test_vlan_ensure_rejects_out_of_range_vlan_id():
    with pytest.raises(HTTPException) as exc:
        runtime._validate_desired_state("network-switch", "vlan.ensure", {"vlan_id": 5000, "name": "prod"})
    assert "vlan_id must be an integer between 1 and 4094" in str(exc.value.detail)


def test_vlan_ensure_rejects_boolean_vlan_id():
    with pytest.raises(HTTPException) as exc:
        runtime._validate_desired_state("network-switch", "vlan.ensure", {"vlan_id": True, "name": "prod"})
    assert "vlan_id must be an integer" in str(exc.value.detail)


def test_vlan_ensure_rejects_unsafe_name():
    with pytest.raises(HTTPException) as exc:
        runtime._validate_desired_state("network-switch", "vlan.ensure", {"vlan_id": 100, "name": "bad;name"})
    assert "VLAN name is unsafe" in str(exc.value.detail)


def test_port_configure_rejects_unknown_fields():
    with pytest.raises(HTTPException) as exc:
        runtime._validate_desired_state(
            "network-switch", "port.configure",
            {"port": "Ethernet1", "mode": "access", "access_vlan": 100, "extra": 1},
        )
    assert "unsupported network-switch port.configure field" in str(exc.value.detail)


def test_port_configure_rejects_unsafe_port_identifier():
    with pytest.raises(HTTPException) as exc:
        runtime._validate_desired_state("network-switch", "port.configure", {"port": "eth 1!", "mode": "access", "access_vlan": 100})
    assert "port identifier is unsafe" in str(exc.value.detail)


def test_port_configure_access_requires_exact_fields():
    with pytest.raises(HTTPException) as exc:
        runtime._validate_desired_state(
            "network-switch", "port.configure",
            {"port": "Ethernet1", "mode": "access", "access_vlan": 100, "trunk_vlans": [100]},
        )
    assert "access port requires only" in str(exc.value.detail)


def test_port_configure_trunk_requires_exact_fields():
    with pytest.raises(HTTPException) as exc:
        runtime._validate_desired_state(
            "network-switch", "port.configure",
            {"port": "Ethernet2", "mode": "trunk", "trunk_vlans": [100], "access_vlan": 100},
        )
    assert "trunk port requires only" in str(exc.value.detail)


def test_port_configure_trunk_rejects_too_many_vlans():
    with pytest.raises(HTTPException) as exc:
        runtime._validate_desired_state(
            "network-switch", "port.configure",
            {"port": "Ethernet2", "mode": "trunk", "trunk_vlans": list(range(1, 66))},
        )
    assert "between 1 and 64 VLAN IDs" in str(exc.value.detail)


def test_port_configure_trunk_rejects_out_of_range_vlan():
    with pytest.raises(HTTPException) as exc:
        runtime._validate_desired_state("network-switch", "port.configure", {"port": "Ethernet2", "mode": "trunk", "trunk_vlans": [100, 5000]})
    assert "VLAN IDs between 1 and 4094" in str(exc.value.detail)


def test_port_configure_trunk_rejects_duplicate_vlans():
    with pytest.raises(HTTPException) as exc:
        runtime._validate_desired_state("network-switch", "port.configure", {"port": "Ethernet2", "mode": "trunk", "trunk_vlans": [100, 100]})
    assert "must be unique" in str(exc.value.detail)


def test_port_configure_trunk_normalizes_sorted_vlans():
    normalized = runtime._validate_desired_state("network-switch", "port.configure", {"port": "Ethernet2", "mode": "trunk", "trunk_vlans": [200, 100]})
    assert normalized["trunk_vlans"] == [100, 200]


def test_port_configure_rejects_unknown_mode():
    with pytest.raises(HTTPException) as exc:
        runtime._validate_desired_state("network-switch", "port.configure", {"port": "Ethernet1", "mode": "hybrid"})
    assert "port mode must be access or trunk" in str(exc.value.detail)


# --- endpoint restrictions: credential-free HTTPS IP-literal fixed root ---

def test_switch_endpoint_rejects_http():
    with pytest.raises(HTTPException) as exc:
        runtime._switch_endpoint({"endpoint": "http://198.51.100.10/restconf/data"})
    assert exc.value.status_code == 422


def test_switch_endpoint_rejects_hostname():
    with pytest.raises(HTTPException) as exc:
        runtime._switch_endpoint({"endpoint": "https://switch.example.test/restconf/data"})
    assert "IP literal" in str(exc.value.detail)


def test_switch_endpoint_rejects_embedded_credentials():
    with pytest.raises(HTTPException) as exc:
        runtime._switch_endpoint({"endpoint": "https://admin:pw@198.51.100.10/restconf/data"})
    assert exc.value.status_code == 422


def test_switch_endpoint_rejects_query_string():
    with pytest.raises(HTTPException) as exc:
        runtime._switch_endpoint({"endpoint": "https://198.51.100.10/restconf/data?x=1"})
    assert exc.value.status_code == 422


def test_switch_endpoint_rejects_non_root_path():
    with pytest.raises(HTTPException) as exc:
        runtime._switch_endpoint({"endpoint": "https://198.51.100.10/restconf/data/extra"})
    assert "fixed /restconf/data root" in str(exc.value.detail)


def test_switch_endpoint_accepts_pinned_ip_literal_root():
    assert runtime._switch_endpoint(SWITCH_PROVIDER) == "https://198.51.100.10/restconf/data"


# --- capability/profile policy enforcement ---

def test_switch_policy_rejects_version_mismatch():
    provider = dict(SWITCH_PROVIDER, api_version="other-version")
    with pytest.raises(HTTPException) as exc:
        runtime._switch_policy(provider)
    assert "do not match the supported RESTCONF profile" in str(exc.value.detail)


def test_switch_policy_rejects_unpinned_profile():
    provider = dict(SWITCH_PROVIDER, capabilities=dict(SWITCH_PROVIDER["capabilities"], profile="other-profile"))
    with pytest.raises(HTTPException) as exc:
        runtime._switch_policy(provider)
    assert "pinned RESTCONF profile" in str(exc.value.detail)


def test_switch_policy_rejects_unknown_capability_fields():
    provider = dict(SWITCH_PROVIDER, capabilities=dict(SWITCH_PROVIDER["capabilities"], extra="no"))
    with pytest.raises(HTTPException) as exc:
        runtime._switch_policy(provider)
    assert exc.value.status_code == 422


def test_switch_policy_rejects_duplicate_port_allowlist_entries():
    provider = dict(SWITCH_PROVIDER, capabilities=dict(SWITCH_PROVIDER["capabilities"], port_allowlist=["Ethernet1", "Ethernet1"]))
    with pytest.raises(HTTPException) as exc:
        runtime._switch_policy(provider)
    assert "unsafe or duplicate" in str(exc.value.detail)


def test_switch_policy_rejects_out_of_range_vlan_allowlist():
    provider = dict(SWITCH_PROVIDER, capabilities=dict(SWITCH_PROVIDER["capabilities"], vlan_allowlist=[100, 5000]))
    with pytest.raises(HTTPException) as exc:
        runtime._switch_policy(provider)
    assert "VLAN allowlist" in str(exc.value.detail)


def test_switch_policy_rejects_port_mode_referencing_unlisted_port():
    provider = dict(SWITCH_PROVIDER, capabilities=dict(SWITCH_PROVIDER["capabilities"], port_modes={"EthernetX": ["access"]}))
    with pytest.raises(HTTPException) as exc:
        runtime._switch_policy(provider)
    assert "port mode policy is invalid" in str(exc.value.detail)


def test_switch_policy_denies_unallowlisted_vlan_for_vlan_ensure():
    with pytest.raises(HTTPException) as exc:
        runtime._switch_policy(SWITCH_PROVIDER, {"vlan_id": 999, "name": "x"}, "vlan.ensure")
    assert "VLAN is not allowlisted" in str(exc.value.detail)


def test_switch_policy_denies_unallowlisted_port_for_port_configure():
    with pytest.raises(HTTPException) as exc:
        runtime._switch_policy(SWITCH_PROVIDER, {"port": "Ethernet9", "mode": "access", "access_vlan": 100}, "port.configure")
    assert "port is not allowlisted" in str(exc.value.detail)


def test_switch_policy_denies_disallowed_mode_for_allowlisted_port():
    # Ethernet1 is allowlisted only for "access" mode.
    with pytest.raises(HTTPException) as exc:
        runtime._switch_policy(SWITCH_PROVIDER, {"port": "Ethernet1", "mode": "trunk", "trunk_vlans": [100]}, "port.configure")
    assert "port mode is not permitted" in str(exc.value.detail)


def test_switch_policy_denies_trunk_vlan_outside_allowlist():
    with pytest.raises(HTTPException) as exc:
        runtime._switch_policy(SWITCH_PROVIDER, {"port": "Ethernet2", "mode": "trunk", "trunk_vlans": [100, 999]}, "port.configure")
    assert "VLAN is not allowlisted" in str(exc.value.detail)


def test_switch_policy_accepts_valid_request_and_returns_normalized_policy():
    policy = runtime._switch_policy(SWITCH_PROVIDER, {"vlan_id": 100, "name": "prod"}, "vlan.ensure")
    assert policy["ports"] == ["Ethernet1", "Ethernet2"]
    assert policy["vlans"] == [100, 200]


def test_switch_credential_profile_delegates_to_shared_credential_loader(monkeypatch):
    monkeypatch.setattr(runtime, "_credential_profile", lambda ref: {"username": "u", "password": "p", "ca_file": None})
    assert runtime._switch_credential_profile("cred_switch000000001") == {"username": "u", "password": "p", "ca_file": None}


# --- fixed RESTCONF path construction ---

def test_switch_vlan_url_uses_fixed_openconfig_path():
    url = runtime._switch_vlan_url(SWITCH_PROVIDER, 100)
    assert url == (
        "https://198.51.100.10/restconf/data"
        "/openconfig-network-instance:network-instances/network-instance=default/vlans/vlan=100"
    )


def test_switch_port_url_rejects_unsafe_port():
    with pytest.raises(HTTPException) as exc:
        runtime._switch_port_url(SWITCH_PROVIDER, "eth 1!")
    assert "port identifier is unsafe" in str(exc.value.detail)


def test_switch_port_url_percent_encodes_safely():
    url = runtime._switch_port_url(SWITCH_PROVIDER, "Ethernet1.100")
    assert url.endswith("/openconfig-interfaces:interfaces/interface=Ethernet1.100")


def test_switch_lldp_url_targets_neighbor_collection():
    url = runtime._switch_lldp_url(SWITCH_PROVIDER, "Ethernet1")
    assert url.endswith("/openconfig-lldp:lldp/interfaces/interface=Ethernet1/neighbors")


# --- collector redaction, bounds, ETag retention, deterministic hashing ---

def test_switch_vlan_snapshot_absent_when_not_found():
    snapshot = runtime._switch_vlan_snapshot(None, 100, "")
    assert snapshot == {"vlan_id": 100, "present": False, "name": "", "etag": ""}


def test_switch_vlan_snapshot_rejects_mismatched_vlan_id():
    raw = {"openconfig-network-instance:vlan": {"config": {"vlan-id": 200, "name": "prod"}}}
    with pytest.raises(HTTPException) as exc:
        runtime._switch_vlan_snapshot(raw, 100, "etag-1")
    assert "did not match requested VLAN" in str(exc.value.detail)


def test_switch_vlan_snapshot_rejects_unsafe_name():
    raw = {"openconfig-network-instance:vlan": {"config": {"vlan-id": 100, "name": "bad;name"}}}
    with pytest.raises(HTTPException) as exc:
        runtime._switch_vlan_snapshot(raw, 100, "etag-1")
    assert "unsafe VLAN name" in str(exc.value.detail)


def test_switch_vlan_snapshot_retains_etag():
    raw = {"openconfig-network-instance:vlan": {"config": {"vlan-id": 100, "name": "prod"}}}
    snapshot = runtime._switch_vlan_snapshot(raw, 100, "etag-1")
    assert snapshot == {"vlan_id": 100, "present": True, "name": "prod", "etag": "etag-1"}


def test_switch_port_snapshot_rejects_mismatched_port():
    raw = {"openconfig-interfaces:interface": {"config": {"name": "Ethernet9"}}}
    with pytest.raises(HTTPException) as exc:
        runtime._switch_port_snapshot(raw, "Ethernet1", "etag-1")
    assert "did not match requested port" in str(exc.value.detail)


def test_switch_port_snapshot_parses_access_mode():
    raw = {
        "openconfig-interfaces:interface": {
            "config": {"name": "Ethernet1"},
            "switched-vlan": {"config": {"interface-mode": "ACCESS", "access-vlan": 100}},
        },
    }
    snapshot = runtime._switch_port_snapshot(raw, "Ethernet1", "etag-1")
    assert snapshot == {"port": "Ethernet1", "mode": "access", "access_vlan": 100, "trunk_vlans": [], "etag": "etag-1"}


def test_switch_port_snapshot_parses_trunk_mode():
    raw = {
        "openconfig-interfaces:interface": {
            "config": {"name": "Ethernet2"},
            "switched-vlan": {"config": {"interface-mode": "TRUNK", "trunk-vlans": [200, 100]}},
        },
    }
    snapshot = runtime._switch_port_snapshot(raw, "Ethernet2", "etag-2")
    assert snapshot == {"port": "Ethernet2", "mode": "trunk", "access_vlan": None, "trunk_vlans": [100, 200], "etag": "etag-2"}


def test_switch_port_snapshot_rejects_invalid_trunk_vlans():
    raw = {
        "openconfig-interfaces:interface": {
            "config": {"name": "Ethernet2"},
            "switched-vlan": {"config": {"interface-mode": "TRUNK", "trunk-vlans": [5000]}},
        },
    }
    with pytest.raises(HTTPException) as exc:
        runtime._switch_port_snapshot(raw, "Ethernet2", "etag-1")
    assert "port response is invalid" in str(exc.value.detail)


def test_switch_lldp_snapshot_redacts_and_bounds_neighbor_fields():
    raw = {
        "openconfig-lldp:neighbors": {
            "neighbor": [
                {"state": {"port-id": "z" * 500, "system-name": "peer-b"}},
                {"state": {"port-id": "peer-a-port", "system-name": "peer-a"}},
            ],
        },
    }
    snapshot = runtime._switch_lldp_snapshot(raw, "Ethernet1", "etag-1")
    assert snapshot["port"] == "Ethernet1"
    assert snapshot["etag"] == "etag-1"
    ports = [entry["port"] for entry in snapshot["neighbors"]]
    assert len(max(ports, key=len)) == 128
    assert snapshot["neighbors"] == sorted(snapshot["neighbors"], key=lambda item: (item["port"], item["system_name"]))


def test_switch_lldp_snapshot_rejects_control_characters():
    raw = {"openconfig-lldp:neighbors": {"neighbor": [{"state": {"port-id": "bad\x00port", "system-name": "peer"}}]}}
    with pytest.raises(HTTPException) as exc:
        runtime._switch_lldp_snapshot(raw, "Ethernet1", "")
    assert "unsafe neighbor data" in str(exc.value.detail)


def test_switch_lldp_snapshot_rejects_too_many_neighbors():
    raw = {"openconfig-lldp:neighbors": {"neighbor": [{"state": {"port-id": f"p{i}", "system-name": "x"}} for i in range(65)]}}
    with pytest.raises(HTTPException) as exc:
        runtime._switch_lldp_snapshot(raw, "Ethernet1", "")
    assert "bounded neighbor limit" in str(exc.value.detail)


# --- request transport: redirect/proxy/response-boundary safety and conditional headers ---

def test_switch_request_rejects_redirect_without_leaking_credentials(monkeypatch):
    class RedirectingOpener:
        def open(self, request, timeout):  # noqa: ANN001
            raise runtime.urllib.error.HTTPError(request.full_url, 302, "Found", {}, None)

    monkeypatch.setattr(runtime.urllib.request, "build_opener", lambda *handlers: RedirectingOpener())
    with pytest.raises(HTTPException) as exc:
        runtime._switch_request_json(
            "GET", "https://198.51.100.10/restconf/data/x",
            credential={"username": "sensitive-user", "password": "sensitive-pass", "ca_file": None},
        )
    assert exc.value.status_code == 502
    assert "redirect rejected" in str(exc.value.detail)
    assert "sensitive" not in str(exc.value.detail)


def test_switch_request_disables_ambient_proxy_inheritance(monkeypatch):
    captured = []

    class FailingOpener:
        def open(self, request, timeout):  # noqa: ANN001
            raise runtime.urllib.error.URLError("offline")

    def fake_build_opener(*handlers):
        captured.extend(handlers)
        return FailingOpener()

    monkeypatch.setattr(runtime.urllib.request, "build_opener", fake_build_opener)
    with pytest.raises(HTTPException):
        runtime._switch_request_json("GET", "https://198.51.100.10/restconf/data/x", credential=CREDENTIAL)
    proxy_handlers = [handler for handler in captured if isinstance(handler, runtime.urllib.request.ProxyHandler)]
    assert len(proxy_handlers) == 1
    assert proxy_handlers[0].proxies == {}


def test_switch_request_allows_not_found_when_requested(monkeypatch):
    class NotFoundOpener:
        def open(self, request, timeout):  # noqa: ANN001
            raise runtime.urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, None)

    monkeypatch.setattr(runtime.urllib.request, "build_opener", lambda *handlers: NotFoundOpener())
    result = runtime._switch_request_json("GET", "https://198.51.100.10/restconf/data/x", credential=CREDENTIAL, allow_not_found=True)
    assert result == (None, "")


def test_switch_request_rejects_oversized_response(monkeypatch):
    class Response:
        headers: dict = {}

        def read(self, n):  # noqa: ANN001
            return b"x" * (1024 * 1024 + 1)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class Opener:
        def open(self, request, timeout):  # noqa: ANN001
            return Response()

    monkeypatch.setattr(runtime.urllib.request, "build_opener", lambda *handlers: Opener())
    with pytest.raises(HTTPException) as exc:
        runtime._switch_request_json("GET", "https://198.51.100.10/restconf/data/x", credential=CREDENTIAL)
    assert "bounded JSON limit" in str(exc.value.detail)


def test_switch_request_rejects_non_object_json(monkeypatch):
    class Response:
        headers: dict = {}

        def read(self, n):  # noqa: ANN001
            return b"[1,2,3]"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class Opener:
        def open(self, request, timeout):  # noqa: ANN001
            return Response()

    monkeypatch.setattr(runtime.urllib.request, "build_opener", lambda *handlers: Opener())
    with pytest.raises(HTTPException) as exc:
        runtime._switch_request_json("GET", "https://198.51.100.10/restconf/data/x", credential=CREDENTIAL)
    assert "non-object JSON" in str(exc.value.detail)


def test_switch_request_sends_conditional_if_match_header(monkeypatch):
    captured = {}

    class Response:
        headers: dict = {}

        def read(self, n):  # noqa: ANN001
            return b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class Opener:
        def open(self, request, timeout):  # noqa: ANN001
            captured["headers"] = {k.lower(): v for k, v in request.header_items()}
            return Response()

    monkeypatch.setattr(runtime.urllib.request, "build_opener", lambda *handlers: Opener())
    runtime._switch_request_json(
        "PUT", "https://198.51.100.10/restconf/data/x", credential=CREDENTIAL,
        body={"a": 1}, etag="etag-9",
    )
    assert captured["headers"]["if-match"] == "etag-9"
    assert captured["headers"]["content-type"] == "application/yang-data+json"


def test_switch_request_rejects_oversized_body():
    with pytest.raises(HTTPException) as exc:
        runtime._switch_request_json(
            "PUT", "https://198.51.100.10/restconf/data/x", credential=CREDENTIAL,
            body={"name": "x" * (1024 * 1024)},
        )
    assert "bounded JSON limit" in str(exc.value.detail)


# --- current-state collection dispatch ---

def test_switch_current_vlan_ensure_allows_not_found(monkeypatch):
    monkeypatch.setattr(runtime, "_switch_request_json", lambda method, url, **kw: (None, ""))
    _, _, current = runtime._switch_current(SWITCH_PROVIDER, CREDENTIAL, "vlan.ensure", {"vlan_id": 100, "name": "prod"})
    assert current["present"] is False


def test_switch_current_port_configure_raises_409_when_absent(monkeypatch):
    monkeypatch.setattr(runtime, "_switch_request_json", lambda method, url, **kw: (None, ""))
    with pytest.raises(HTTPException) as exc:
        runtime._switch_current(SWITCH_PROVIDER, CREDENTIAL, "port.configure", {"port": "Ethernet1", "mode": "access", "access_vlan": 100})
    assert exc.value.status_code == 409
    assert "port is not present" in str(exc.value.detail)


def test_switch_current_lldp_observe_collects_every_allowlisted_port(monkeypatch):
    calls = []

    def fake_request(method, url, **kw):
        calls.append(url)
        return {"openconfig-lldp:neighbors": {"neighbor": []}}, "etag-x"

    monkeypatch.setattr(runtime, "_switch_request_json", fake_request)
    _, _, current = runtime._switch_current(SWITCH_PROVIDER, CREDENTIAL, "lldp.observe", {})
    assert len(current["ports"]) == 2
    assert len(calls) == 2


def test_switch_current_lldp_observe_rejects_empty_collector_response(monkeypatch):
    monkeypatch.setattr(runtime, "_switch_request_json", lambda method, url, **kw: (None, ""))
    with pytest.raises(HTTPException) as exc:
        runtime._switch_current(SWITCH_PROVIDER, CREDENTIAL, "lldp.observe", {})
    assert "empty response" in str(exc.value.detail)


# --- deterministic diff ---

def test_switch_diff_lldp_observe_is_always_empty():
    assert runtime._switch_diff("lldp.observe", {"ports": []}, {}) == []


def test_switch_diff_vlan_ensure_detects_missing_vlan():
    current = {"present": False, "name": ""}
    diff = runtime._switch_diff("vlan.ensure", current, {"vlan_id": 100, "name": "prod"})
    assert diff and diff[0]["field"] == "vlan.100"


def test_switch_diff_vlan_ensure_no_diff_when_converged():
    current = {"present": True, "name": "prod"}
    assert runtime._switch_diff("vlan.ensure", current, {"vlan_id": 100, "name": "prod"}) == []


def test_switch_diff_access_port_exact_match_yields_no_diff():
    current = {"mode": "access", "access_vlan": 100, "trunk_vlans": []}
    desired = {"port": "Ethernet1", "mode": "access", "access_vlan": 100}
    assert runtime._switch_diff("port.configure", current, desired) == []


def test_switch_diff_access_port_mismatch_yields_diff():
    current = {"mode": "trunk", "access_vlan": None, "trunk_vlans": [100]}
    desired = {"port": "Ethernet1", "mode": "access", "access_vlan": 100}
    diff = runtime._switch_diff("port.configure", current, desired)
    assert diff and diff[0]["field"] == "port.Ethernet1.switched_vlan"


def test_switch_diff_trunk_port_exact_match_yields_no_diff():
    current = {"mode": "trunk", "access_vlan": None, "trunk_vlans": [100, 200]}
    desired = {"port": "Ethernet2", "mode": "trunk", "trunk_vlans": [100, 200]}
    assert runtime._switch_diff("port.configure", current, desired) == []


# --- fixed mutation payloads ---

def test_apply_switch_vlan_ensure_puts_openconfig_body(monkeypatch):
    captured = {}

    def fake_request(method, url, *, credential, body=None, etag="", allow_not_found=False):  # noqa: ANN001
        captured.update(method=method, url=url, body=body, etag=etag)
        return {}, ""

    monkeypatch.setattr(runtime, "_switch_request_json", fake_request)
    runtime._apply_switch(
        "vlan.ensure", SWITCH_PROVIDER, "https://198.51.100.10/restconf/data/x",
        {"etag": "etag-1"}, {"vlan_id": 100, "name": "prod"}, CREDENTIAL,
    )
    assert captured["method"] == "PUT"
    assert captured["etag"] == "etag-1"
    assert captured["body"] == {"openconfig-network-instance:vlan": {"vlan-id": 100, "config": {"vlan-id": 100, "name": "prod"}}}


def test_apply_switch_port_configure_access_puts_access_body(monkeypatch):
    captured = {}

    def fake_request(method, url, *, credential, body=None, etag="", allow_not_found=False):  # noqa: ANN001
        captured.update(body=body)
        return {}, ""

    monkeypatch.setattr(runtime, "_switch_request_json", fake_request)
    runtime._apply_switch(
        "port.configure", SWITCH_PROVIDER, "url", {"etag": ""},
        {"port": "Ethernet1", "mode": "access", "access_vlan": 100}, CREDENTIAL,
    )
    assert captured["body"]["openconfig-interfaces:interface"]["switched-vlan"]["config"] == {"interface-mode": "ACCESS", "access-vlan": 100}


def test_apply_switch_port_configure_trunk_puts_trunk_body(monkeypatch):
    captured = {}

    def fake_request(method, url, *, credential, body=None, etag="", allow_not_found=False):  # noqa: ANN001
        captured.update(body=body)
        return {}, ""

    monkeypatch.setattr(runtime, "_switch_request_json", fake_request)
    runtime._apply_switch(
        "port.configure", SWITCH_PROVIDER, "url", {"etag": ""},
        {"port": "Ethernet2", "mode": "trunk", "trunk_vlans": [100, 200]}, CREDENTIAL,
    )
    assert captured["body"]["openconfig-interfaces:interface"]["switched-vlan"]["config"] == {"interface-mode": "TRUNK", "trunk-vlans": [100, 200]}


def test_apply_switch_lldp_observe_is_a_pure_no_op(monkeypatch):
    called = []
    monkeypatch.setattr(runtime, "_switch_request_json", lambda *a, **kw: called.append(1))
    runtime._apply_switch("lldp.observe", SWITCH_PROVIDER, "url", {}, {}, CREDENTIAL)
    assert called == []


# --- active verification ---

def test_switch_verify_lldp_observe_true_when_neighbors_collected():
    assert runtime._switch_verify("lldp.observe", {"ports": [{"port": "Ethernet1", "neighbors": []}]}, {}) is True


def test_switch_verify_lldp_observe_false_when_no_ports_collected():
    assert runtime._switch_verify("lldp.observe", {"ports": []}, {}) is False


def test_switch_verify_vlan_ensure_true_when_converged():
    assert runtime._switch_verify("vlan.ensure", {"present": True, "name": "prod"}, {"vlan_id": 100, "name": "prod"}) is True


def test_switch_verify_vlan_ensure_false_when_not_converged():
    assert runtime._switch_verify("vlan.ensure", {"present": False, "name": ""}, {"vlan_id": 100, "name": "prod"}) is False


# --- preview: full pipeline via runtime.preview() ---

def test_preview_denies_unallowlisted_vlan_before_dispatch(monkeypatch):
    called = []
    monkeypatch.setattr(runtime, "_switch_credential_profile", lambda ref: CREDENTIAL)
    monkeypatch.setattr(runtime, "_switch_request_json", lambda *a, **kw: called.append(1))
    typed = _typed({"vlan_id": 999, "name": "prod"}, "vlan.ensure")
    with pytest.raises(HTTPException) as exc:
        runtime.preview({"parameters": {"typed_plan": typed}})
    assert exc.value.status_code == 422
    assert called == []


def test_preview_vlan_ensure_reports_diff_when_not_present(monkeypatch):
    monkeypatch.setattr(runtime, "_switch_credential_profile", lambda ref: CREDENTIAL)
    monkeypatch.setattr(runtime, "_switch_request_json", lambda method, url, **kw: (None, ""))
    typed = _typed({"vlan_id": 100, "name": "prod"}, "vlan.ensure")
    preview = runtime.preview({"parameters": {"typed_plan": typed}})
    assert preview["provider_kind"] == "network-switch"
    assert preview["credential_material_returned"] is False
    assert preview["secret_output_suppressed"] is True
    assert preview["arbitrary_cli"] is False
    assert preview["arbitrary_shell"] is False
    assert preview["diff"][0]["field"] == "vlan.100"


def test_preview_port_configure_requires_allowlisted_port_present(monkeypatch):
    monkeypatch.setattr(runtime, "_switch_credential_profile", lambda ref: CREDENTIAL)
    monkeypatch.setattr(runtime, "_switch_request_json", lambda method, url, **kw: (None, ""))
    typed = _typed({"port": "Ethernet1", "mode": "access", "access_vlan": 100}, "port.configure")
    with pytest.raises(HTTPException) as exc:
        runtime.preview({"parameters": {"typed_plan": typed}})
    assert exc.value.status_code == 409
    assert "port is not present" in str(exc.value.detail)


def test_preview_lldp_observe_collects_all_allowlisted_ports(monkeypatch):
    monkeypatch.setattr(runtime, "_switch_credential_profile", lambda ref: CREDENTIAL)
    seen_urls = []

    def fake_request(method, url, **kw):
        seen_urls.append(url)
        return {"openconfig-lldp:neighbors": {"neighbor": []}}, "etag-1"

    monkeypatch.setattr(runtime, "_switch_request_json", fake_request)
    typed = _typed({}, "lldp.observe")
    preview = runtime.preview({"parameters": {"typed_plan": typed}})
    assert preview["diff"] == []
    assert len(preview["current"]["ports"]) == 2
    assert len(seen_urls) == 2


# --- execute: drift rejection, conditional mutation, idempotence, convergence, ticket safety ---

def test_signed_vlan_ensure_execution_rejects_drift_and_then_converges(monkeypatch):
    desired = {"vlan_id": 100, "name": "prod"}
    before = {"vlan_id": 100, "present": False, "name": "", "etag": ""}
    preview = {
        "provider_kind": "network-switch", "operation": "vlan.ensure", "current": before,
        "current_hash": runtime.sha256_hex(before), "active_probe": True,
        "secret_output_suppressed": True, "credential_material_returned": False,
        "arbitrary_cli": False, "arbitrary_shell": False,
    }
    typed = _typed(desired, "vlan.ensure", preview)
    key = "execution-key-0123456789abcdef0123456789abcdef"
    ticket, signature = _signed_ticket(typed, key)
    monkeypatch.setattr(runtime, "EXECUTION_ENABLED", True)
    monkeypatch.setattr(runtime, "EXECUTION_KEY", key)
    monkeypatch.setattr(runtime, "VERIFY_ATTEMPTS", 1)
    monkeypatch.setattr(runtime, "VERIFY_DELAY_SECONDS", 0)
    monkeypatch.setattr(runtime, "_switch_credential_profile", lambda ref: CREDENTIAL)

    drift = {"vlan_id": 100, "present": True, "name": "other", "etag": "etag-drift"}
    monkeypatch.setattr(runtime, "_switch_current", lambda provider, credential, operation, desired: ("url", {"etag": "etag-drift"}, drift))
    applied = []
    monkeypatch.setattr(runtime, "_apply_switch", lambda *args: applied.append(args))
    runtime._USED_TICKETS.clear()
    with pytest.raises(HTTPException) as exc:
        runtime.execute(ticket, signature)
    assert exc.value.status_code == 409
    assert applied == []

    ticket, signature = _signed_ticket(typed, key)
    after = {"vlan_id": 100, "present": True, "name": "prod", "etag": "etag-2"}
    observations = iter([
        ("url", {"etag": ""}, before),
        ("url", {"etag": "etag-2"}, after),
    ])
    monkeypatch.setattr(runtime, "_switch_current", lambda provider, credential, operation, desired: next(observations))
    runtime._USED_TICKETS.clear()
    result = runtime.execute(ticket, signature)
    assert result["state"] == "SUCCEEDED"
    assert result["verification"]["checks"][1]["id"] == "network-switch-active-verify"
    assert result["verification"]["evidence"]["raw_credentials_returned"] is False
    assert applied and applied[0][0] == "vlan.ensure"


def test_signed_vlan_ensure_is_idempotent_when_already_converged(monkeypatch):
    desired = {"vlan_id": 100, "name": "prod"}
    already = {"vlan_id": 100, "present": True, "name": "prod", "etag": "etag-1"}
    preview = {
        "provider_kind": "network-switch", "operation": "vlan.ensure", "current": already,
        "current_hash": runtime.sha256_hex(already), "active_probe": True,
        "secret_output_suppressed": True, "credential_material_returned": False,
        "arbitrary_cli": False, "arbitrary_shell": False,
    }
    typed = _typed(desired, "vlan.ensure", preview)
    key = "execution-key-0123456789abcdef0123456789abcdef"
    ticket, signature = _signed_ticket(typed, key)
    monkeypatch.setattr(runtime, "EXECUTION_ENABLED", True)
    monkeypatch.setattr(runtime, "EXECUTION_KEY", key)
    monkeypatch.setattr(runtime, "VERIFY_ATTEMPTS", 1)
    monkeypatch.setattr(runtime, "VERIFY_DELAY_SECONDS", 0)
    monkeypatch.setattr(runtime, "_switch_credential_profile", lambda ref: CREDENTIAL)
    monkeypatch.setattr(runtime, "_switch_current", lambda *a: ("url", {"etag": "etag-1"}, already))
    applied = []
    monkeypatch.setattr(runtime, "_apply_switch", lambda *args: applied.append(args))
    runtime._USED_TICKETS.clear()
    result = runtime.execute(ticket, signature)
    assert result["state"] == "SUCCEEDED"
    assert applied == []
    assert result["verification"]["evidence"]["mutation_applied"] is False


def test_signed_lldp_observe_execution_performs_no_mutation_and_reverifies(monkeypatch):
    desired: dict = {}
    before = {"ports": [{"port": "Ethernet1", "neighbors": [{"port": "peer-a", "system_name": "leaf-02"}], "etag": "etag-1"}]}
    preview = {
        "provider_kind": "network-switch", "operation": "lldp.observe", "current": before,
        "current_hash": runtime.sha256_hex(before), "active_probe": True,
        "secret_output_suppressed": True, "credential_material_returned": False,
        "arbitrary_cli": False, "arbitrary_shell": False,
    }
    typed = _typed(desired, "lldp.observe", preview)
    key = "execution-key-0123456789abcdef0123456789abcdef"
    ticket, signature = _signed_ticket(typed, key)
    monkeypatch.setattr(runtime, "EXECUTION_ENABLED", True)
    monkeypatch.setattr(runtime, "EXECUTION_KEY", key)
    monkeypatch.setattr(runtime, "VERIFY_ATTEMPTS", 1)
    monkeypatch.setattr(runtime, "VERIFY_DELAY_SECONDS", 0)
    monkeypatch.setattr(runtime, "_switch_credential_profile", lambda ref: CREDENTIAL)
    monkeypatch.setattr(runtime, "_switch_current", lambda *a: ("url", {}, before))
    applied = []
    monkeypatch.setattr(runtime, "_apply_switch", lambda *args: applied.append(args))
    runtime._USED_TICKETS.clear()
    result = runtime.execute(ticket, signature)
    assert result["state"] == "SUCCEEDED"
    assert applied == []
    assert result["verification"]["evidence"]["mutation_applied"] is False


def test_signed_lldp_observe_execution_fails_when_neighbors_disappear(monkeypatch):
    desired: dict = {}
    before = {"ports": []}
    preview = {
        "provider_kind": "network-switch", "operation": "lldp.observe", "current": before,
        "current_hash": runtime.sha256_hex(before), "active_probe": True,
        "secret_output_suppressed": True, "credential_material_returned": False,
        "arbitrary_cli": False, "arbitrary_shell": False,
    }
    typed = _typed(desired, "lldp.observe", preview)
    key = "execution-key-0123456789abcdef0123456789abcdef"
    ticket, signature = _signed_ticket(typed, key)
    monkeypatch.setattr(runtime, "EXECUTION_ENABLED", True)
    monkeypatch.setattr(runtime, "EXECUTION_KEY", key)
    monkeypatch.setattr(runtime, "VERIFY_ATTEMPTS", 1)
    monkeypatch.setattr(runtime, "VERIFY_DELAY_SECONDS", 0)
    monkeypatch.setattr(runtime, "_switch_credential_profile", lambda ref: CREDENTIAL)
    monkeypatch.setattr(runtime, "_switch_current", lambda *a: ("url", {}, before))
    runtime._USED_TICKETS.clear()
    result = runtime.execute(ticket, signature)
    assert result["state"] == "FAILED"


def test_switch_execution_ticket_cannot_be_replayed(monkeypatch):
    desired = {"vlan_id": 100, "name": "prod"}
    already = {"vlan_id": 100, "present": True, "name": "prod", "etag": "etag-1"}
    preview = {
        "provider_kind": "network-switch", "operation": "vlan.ensure", "current": already,
        "current_hash": runtime.sha256_hex(already), "active_probe": True,
        "secret_output_suppressed": True, "credential_material_returned": False,
        "arbitrary_cli": False, "arbitrary_shell": False,
    }
    typed = _typed(desired, "vlan.ensure", preview)
    key = "execution-key-0123456789abcdef0123456789abcdef"
    ticket, signature = _signed_ticket(typed, key)
    monkeypatch.setattr(runtime, "EXECUTION_ENABLED", True)
    monkeypatch.setattr(runtime, "EXECUTION_KEY", key)
    monkeypatch.setattr(runtime, "VERIFY_ATTEMPTS", 1)
    monkeypatch.setattr(runtime, "VERIFY_DELAY_SECONDS", 0)
    monkeypatch.setattr(runtime, "_switch_credential_profile", lambda ref: CREDENTIAL)
    monkeypatch.setattr(runtime, "_switch_current", lambda *a: ("url", {"etag": "etag-1"}, already))
    runtime._USED_TICKETS.clear()
    assert runtime.execute(ticket, signature)["state"] == "SUCCEEDED"
    with pytest.raises(HTTPException) as exc:
        runtime.execute(ticket, signature)
    assert exc.value.status_code == 409
    assert "already been used" in str(exc.value.detail)


def test_switch_execution_ticket_rejects_bad_signature(monkeypatch):
    typed = _typed({"vlan_id": 100, "name": "prod"}, "vlan.ensure")
    key = "execution-key-0123456789abcdef0123456789abcdef"
    ticket, _ = _signed_ticket(typed, key)
    monkeypatch.setattr(runtime, "EXECUTION_ENABLED", True)
    monkeypatch.setattr(runtime, "EXECUTION_KEY", key)
    runtime._USED_TICKETS.clear()
    with pytest.raises(HTTPException) as exc:
        runtime.execute(ticket, "0" * 64)
    assert exc.value.status_code == 401


def test_switch_execution_ticket_rejects_expired(monkeypatch):
    typed = _typed({"vlan_id": 100, "name": "prod"}, "vlan.ensure")
    key = "execution-key-0123456789abcdef0123456789abcdef"
    plan = {"parameters": {"typed_plan": typed}}
    ticket = {
        "changeset_id": "chg_switch000000002",
        "plan_hash": runtime.sha256_hex(plan),
        "plan": plan,
        "preconditions": {
            "operation_job_id": "opj_switch000000002", "operation_plan_id": "opn_switch000000002",
            "executor": "infrastructure-provider-worker", "typed_plan_hash": typed["plan_hash"], "policy_generation": 1,
        },
        "issued_at": int(time.time()) - 1000,
        "expires_at": int(time.time()) - 500,
    }
    signature = hmac.new(key.encode(), _canonical(ticket).encode(), hashlib.sha256).hexdigest()
    monkeypatch.setattr(runtime, "EXECUTION_ENABLED", True)
    monkeypatch.setattr(runtime, "EXECUTION_KEY", key)
    runtime._USED_TICKETS.clear()
    with pytest.raises(HTTPException) as exc:
        runtime.execute(ticket, signature)
    assert exc.value.status_code == 409
    assert "expired" in str(exc.value.detail)
