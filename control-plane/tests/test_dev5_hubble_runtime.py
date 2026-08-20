from __future__ import annotations

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
from hermes_control_plane import kubernetes as kubernetes_broker  # noqa: E402
from hermes_control_plane.main import app  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin"}
CREDENTIAL_SERVICE = {"Authorization": "Bearer test-credential-service"}
FP = "SHA256:" + "H" * 43


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(app) as c:
        yield c


def _cluster_and_target(client: TestClient) -> tuple[dict, dict]:
    env = client.post("/v1/environments", headers=ADMIN, json={"name": "Hubble Runtime", "risk_level": "HIGH"}).json()
    ssh = client.post(
        "/v1/internal/credential-refs/sync",
        headers=CREDENTIAL_SERVICE,
        json={"id": "cred_hubblessh1234", "name": "hubble-ssh", "kind": "ssh-key", "provider": "credential-service", "status": "configured", "metadata": {"fingerprint": "sha256:ssh"}},
    ).json()
    server = client.post(
        "/v1/servers",
        headers=ADMIN,
        json={"hostname": "hubble-node-1", "environment_id": env["id"], "management_ip": "10.77.0.10", "ssh_port": 22, "ssh_user": "ubuntu", "host_fingerprint": FP, "connection_mode": "agent", "credential_ref": ssh["id"]},
    ).json()
    blueprint = client.post(
        "/v1/cluster-blueprints",
        headers=ADMIN,
        json={"name": "dev5-hubble-blueprint", "provider": "k3s", "provider_version": "v1.35.6+k3s1", "kubernetes_version": "1.35.6", "network_plugin": "cilium", "hubble_enabled": True, "radar_enabled": False, "addon_versions": {"cilium": "1.19.4", "hubble": "1.19.4", "hermes-agent": "0.5.11-dev.5"}},
    ).json()
    profile = client.post(
        "/v1/cluster-profiles",
        headers=ADMIN,
        json={"name": "dev5-hubble-profile", "environment_id": env["id"], "blueprint_id": blueprint["id"], "server_ids": [server["id"]]},
    ).json()
    cluster = client.post(
        "/v1/clusters",
        headers=ADMIN,
        json={"name": "dev5-hubble-cluster", "environment_id": env["id"], "profile_id": profile["id"]},
    ).json()
    kube = client.post(
        "/v1/internal/credential-refs/sync",
        headers=CREDENTIAL_SERVICE,
        json={"id": "cred_hubblekube123", "name": "hubble-kube", "kind": "kubeconfig", "provider": "credential-service", "status": "configured", "metadata": {"sha256": "0" * 64}},
    ).json()
    target = client.post(
        "/v1/targets",
        headers=ADMIN,
        json={"name": "dev5-hubble-k8s", "kind": "kubernetes", "environment_id": env["id"], "credential_ref": kube["id"], "connection_mode": "direct", "scope": {"namespace_allowlist": ["apps"]}},
    ).json()
    return cluster, target


def _batch() -> dict:
    return {
        "provider": "cilium-hubble",
        "transport": "hubble-relay-via-port-forward",
        "observed_at": 1770000000,
        "events": [{
            "time": "2026-08-20T10:00:00Z",
            "verdict": "FORWARDED",
            "source": {"namespace": "apps", "workload": "Deployment/api"},
            "destination": {"namespace": "apps", "workload": "Service/web"},
            "protocol": "TCP",
            "destination_port": 443,
            "http": None,
            "drop_reason": None,
            "traffic_direction": "EGRESS",
            "is_reply": False,
            "fingerprint": "a" * 64,
        }],
        "summary": {"observed_at": 1770000000, "event_count": 1, "verdict_counts": {"FORWARDED": 1}},
        "raw_flow_bodies_returned": False,
        "rejected_lines": 0,
    }


def test_hubble_live_collection_is_brokered_persisted_and_deduplicated(client: TestClient, monkeypatch):
    cluster, target = _cluster_and_target(client)
    seen = []

    async def fake_post(path: str, payload: dict) -> dict:
        seen.append((path, payload))
        return _batch()

    monkeypatch.setattr(kubernetes_broker, "post", fake_post)
    url = f"/v1/clusters/{cluster['id']}/network/live"
    first = client.post(url, headers=ADMIN, json={"native_target_id": target["id"], "last": 25, "since_seconds": 30})
    assert first.status_code == 200, first.text
    assert first.json()["events"][0]["fingerprint"] == "a" * 64
    assert first.json()["raw_flow_bodies_returned"] is False
    second = client.post(url, headers=ADMIN, json={"native_target_id": target["id"], "last": 25})
    assert second.status_code == 200, second.text
    assert second.json()["events"] == []
    assert seen[0][0] == "/v1/hubble/collect"
    assert seen[0][1]["target_snapshot"]["scope"]["namespace_allowlist"] == ["apps"]

    history = client.get(f"/v1/clusters/{cluster['id']}/network/history?limit=10", headers=ADMIN)
    assert history.status_code == 200, history.text
    assert len(history.json()["events"]) == 1
    assert history.json()["bounded"] is True


def test_hubble_live_rejects_cross_environment_target(client: TestClient):
    cluster, _ = _cluster_and_target(client)
    other = client.post("/v1/environments", headers=ADMIN, json={"name": "Other", "risk_level": "LOW"}).json()
    kube = client.post(
        "/v1/internal/credential-refs/sync",
        headers=CREDENTIAL_SERVICE,
        json={"id": "cred_otherkube1234", "name": "other-kube", "kind": "kubeconfig", "provider": "credential-service", "status": "configured", "metadata": {"sha256": "1" * 64}},
    ).json()
    target = client.post(
        "/v1/targets", headers=ADMIN,
        json={"name": "other-k8s", "kind": "kubernetes", "environment_id": other["id"], "credential_ref": kube["id"], "scope": {}},
    ).json()
    response = client.post(f"/v1/clusters/{cluster['id']}/network/live", headers=ADMIN, json={"native_target_id": target["id"]})
    assert response.status_code == 403


def test_hubble_live_refuses_unsanitized_broker_attestation(client: TestClient, monkeypatch):
    cluster, target = _cluster_and_target(client)
    batch = _batch()
    batch["raw_flow_bodies_returned"] = True

    async def fake_post(*_: object, **__: object) -> dict:
        return batch

    monkeypatch.setattr(kubernetes_broker, "post", fake_post)
    response = client.post(f"/v1/clusters/{cluster['id']}/network/live", headers=ADMIN, json={"native_target_id": target["id"]})
    assert response.status_code == 502


def test_hubble_live_drops_event_with_unexpected_nested_raw_fields(client: TestClient, monkeypatch):
    cluster, target = _cluster_and_target(client)
    batch = _batch()
    batch["events"][0]["http"] = {"method": "GET", "status_class": "2xx", "url": "https://should-not-leak.invalid"}

    async def fake_post(*_: object, **__: object) -> dict:
        return batch

    monkeypatch.setattr(kubernetes_broker, "post", fake_post)
    response = client.post(f"/v1/clusters/{cluster['id']}/network/live", headers=ADMIN, json={"native_target_id": target["id"]})
    assert response.status_code == 200, response.text
    assert response.json()["events"] == []
    history = client.get(f"/v1/clusters/{cluster['id']}/network/history", headers=ADMIN)
    assert history.json()["events"] == []
