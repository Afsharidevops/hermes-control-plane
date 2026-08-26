from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from hermes_node_agent import host_observation
from hermes_node_agent import host_observer
from hermes_node_agent.host_observer import app


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    sys_net = tmp_path / "sys" / "class" / "net"
    iface = sys_net / "eth0"
    iface.mkdir(parents=True)
    (iface / "operstate").write_text("up\n", encoding="utf-8")
    (iface / "mtu").write_text("1500\n", encoding="utf-8")
    vlan_config = tmp_path / "proc" / "net" / "vlan" / "config"
    vlan_config.parent.mkdir(parents=True)
    vlan_config.write_text("VLAN Dev name | VLAN ID\n100 eth0 | eth0\n", encoding="utf-8")
    return sys_net, vlan_config


def test_collect_host_network_is_bounded_redacted_and_deterministic(tmp_path):
    sys_net, vlan_config = _roots(tmp_path)
    result = host_observation.collect_host_network(
        collector_identity="host-observer-a",
        sys_net_root=sys_net,
        vlan_config_path=vlan_config,
        observed_at=100,
    )
    assert result["status"] == "PASS"
    assert result["facts"] == {"interfaces": [{"name": "eth0", "state": "up", "mtu": 1500}], "bond_count": 0, "vlan_count": 1}
    assert "address" not in str(result["facts"]).lower()
    assert "mac" not in str(result["facts"]).lower()
    assert result["mutation_commands_executed"] is False
    assert result["credential_material_returned"] is False
    assert result["observation_hash"] == host_observation.collect_host_network(
        collector_identity="host-observer-a", sys_net_root=sys_net, vlan_config_path=vlan_config, observed_at=100
    )["observation_hash"]


def test_collect_host_network_skips_when_host_roots_are_absent(tmp_path):
    result = host_observation.collect_host_network(
        collector_identity="host-observer-a",
        sys_net_root=tmp_path / "absent-sys",
        vlan_config_path=tmp_path / "absent-proc",
        observed_at=100,
    )
    assert result["status"] == "SKIP"
    assert result["host_roots_visible"] is False


def test_collector_route_requires_dedicated_token_and_strict_empty_body(monkeypatch, tmp_path):
    sys_net, vlan_config = _roots(tmp_path)
    monkeypatch.setenv("HERMES_HOST_OBSERVER_TOKEN", "observer-token")
    monkeypatch.setenv("HERMES_HOST_OBSERVER_IDENTITY", "host-observer-a")
    monkeypatch.setattr(host_observer, "HOST_SYS_NET_ROOT", sys_net)
    monkeypatch.setattr(host_observer, "HOST_VLAN_CONFIG_PATH", vlan_config)
    client = TestClient(app)

    assert client.post("/v1/collectors/host-network", json={}).status_code == 401
    assert client.post("/v1/collectors/host-network", headers={"Authorization": "Bearer observer-token"}, json={"target": "forbidden"}).status_code == 422
    response = client.post("/v1/collectors/host-network", headers={"Authorization": "Bearer observer-token"}, json={})
    assert response.status_code == 200
    assert response.json()["collector_kind"] == "host-network-local-v1"
    assert client.post("/v1/provider/execute", headers={"Authorization": "Bearer observer-token"}, json={}).status_code == 404


def test_host_observer_does_not_accept_host_root_overrides(monkeypatch, tmp_path):
    sys_net, vlan_config = _roots(tmp_path)
    monkeypatch.setenv("HERMES_HOST_OBSERVER_TOKEN", "observer-token")
    monkeypatch.setenv("HERMES_HOST_OBSERVER_IDENTITY", "host-observer-a")
    monkeypatch.setenv("HERMES_HOST_OBSERVER_SYS_NET_ROOT", str(tmp_path / "untrusted-sys"))
    monkeypatch.setenv("HERMES_HOST_OBSERVER_VLAN_CONFIG_PATH", str(tmp_path / "untrusted-vlan"))
    monkeypatch.setattr(host_observer, "HOST_SYS_NET_ROOT", sys_net)
    monkeypatch.setattr(host_observer, "HOST_VLAN_CONFIG_PATH", vlan_config)
    response = TestClient(app).post(
        "/v1/collectors/host-network",
        headers={"Authorization": "Bearer observer-token"},
        json={},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "PASS"
    assert response.json()["facts"]["interfaces"] == [{"name": "eth0", "state": "up", "mtu": 1500}]
