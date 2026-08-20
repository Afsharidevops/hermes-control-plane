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
FP = "SHA256:" + "D" * 43


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(app) as c:
        yield c


def _cluster_and_target(client: TestClient) -> tuple[dict, dict]:
    env = client.post("/v1/environments", headers=ADMIN, json={"name": "Diagnostics Runtime", "risk_level": "HIGH"}).json()
    ssh = client.post(
        "/v1/internal/credential-refs/sync",
        headers=CREDENTIAL_SERVICE,
        json={"id": "cred_diagssh12345", "name": "diag-ssh", "kind": "ssh-key", "provider": "credential-service", "status": "configured", "metadata": {"fingerprint": "sha256:ssh"}},
    ).json()
    server = client.post(
        "/v1/servers",
        headers=ADMIN,
        json={"hostname": "diag-node-1", "environment_id": env["id"], "management_ip": "10.88.0.10", "ssh_port": 22, "ssh_user": "ubuntu", "host_fingerprint": FP, "connection_mode": "agent", "credential_ref": ssh["id"]},
    ).json()
    blueprint = client.post(
        "/v1/cluster-blueprints",
        headers=ADMIN,
        json={"name": "dev5-diag-blueprint", "provider": "k3s", "provider_version": "v1.35.6+k3s1", "kubernetes_version": "1.35.6", "network_plugin": "cilium", "hubble_enabled": True, "radar_enabled": False, "addon_versions": {"cilium": "1.19.4", "hubble": "1.19.4", "hermes-agent": "0.5.11-dev.5"}},
    ).json()
    profile = client.post(
        "/v1/cluster-profiles",
        headers=ADMIN,
        json={"name": "dev5-diag-profile", "environment_id": env["id"], "blueprint_id": blueprint["id"], "server_ids": [server["id"]]},
    ).json()
    cluster = client.post(
        "/v1/clusters",
        headers=ADMIN,
        json={"name": "dev5-diag-cluster", "environment_id": env["id"], "profile_id": profile["id"]},
    ).json()
    kube = client.post(
        "/v1/internal/credential-refs/sync",
        headers=CREDENTIAL_SERVICE,
        json={"id": "cred_diagkube1234", "name": "diag-kube", "kind": "kubeconfig", "provider": "credential-service", "status": "configured", "metadata": {"sha256": "0" * 64}},
    ).json()
    target = client.post(
        "/v1/targets",
        headers=ADMIN,
        json={"name": "dev5-diag-k8s", "kind": "kubernetes", "environment_id": env["id"], "credential_ref": kube["id"], "connection_mode": "direct", "scope": {"namespace_allowlist": ["apps"], "cluster_read": False}},
    ).json()
    return cluster, target


def _result() -> dict:
    return {
        "provider": "hermes-native-kubernetes-diagnostics",
        "observed_at": 1770000100,
        "overall_status": "WARN",
        "checks": [
            {"id": "pods.health", "status": "WARN", "summary": "1 restart hotspot.", "evidence": {"restart_hotspots": [{"pod": "apps/api", "restart_count": 8}]}},
            {"id": "security.privileged", "status": "PASS", "summary": "No privileged containers observed.", "evidence": {}},
        ],
        "summary": {"PASS": 1, "WARN": 1, "FAIL": 0, "SKIP": 0},
        "secret_data_requested": False,
        "mutation_commands_executed": False,
        "policy_scope": {"namespace_allowlist": ["apps"], "namespace_denylist": [], "cluster_read": False},
    }


def test_native_diagnostics_are_brokered_typed_and_audited(client: TestClient, monkeypatch):
    cluster, target = _cluster_and_target(client)
    seen = []

    async def fake_post(path: str, payload: dict) -> dict:
        seen.append((path, payload))
        return _result()

    monkeypatch.setattr(kubernetes_broker, "post", fake_post)
    response = client.post(
        f"/v1/clusters/{cluster['id']}/diagnostics/run",
        headers=ADMIN,
        json={"native_target_id": target["id"], "checks": ["pods.health", "security.privileged"]},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["cluster_id"] == cluster["id"]
    assert body["native_target_id"] == target["id"]
    assert body["provider"] == "hermes-native-kubernetes-diagnostics"
    assert body["mutation_commands_executed"] is False
    assert seen[0][0] == "/v1/diagnostics/run"
    assert seen[0][1]["target_snapshot"]["scope"]["namespace_allowlist"] == ["apps"]
    assert seen[0][1]["checks"] == ["pods.health", "security.privileged"]

    audit = client.get("/v1/audit?limit=20", headers=ADMIN)
    assert audit.status_code == 200
    assert any(row["event_type"] == "kubernetes.diagnostics.executed" for row in audit.json())


def test_native_diagnostics_reject_sensitive_or_malformed_broker_evidence(client: TestClient, monkeypatch):
    cluster, target = _cluster_and_target(client)

    async def fake_post(path: str, payload: dict) -> dict:
        result = _result()
        result["checks"][0]["evidence"] = {"env": "TOPSECRET"}
        return result

    monkeypatch.setattr(kubernetes_broker, "post", fake_post)
    response = client.post(
        f"/v1/clusters/{cluster['id']}/diagnostics/run",
        headers=ADMIN,
        json={"native_target_id": target["id"], "checks": ["pods.health"]},
    )
    assert response.status_code == 502
    assert "forbidden sensitive field" in response.text


def test_native_diagnostics_reject_broker_mutation_attestation(client: TestClient, monkeypatch):
    cluster, target = _cluster_and_target(client)

    async def fake_post(path: str, payload: dict) -> dict:
        result = _result()
        result["mutation_commands_executed"] = True
        return result

    monkeypatch.setattr(kubernetes_broker, "post", fake_post)
    response = client.post(
        f"/v1/clusters/{cluster['id']}/diagnostics/run",
        headers=ADMIN,
        json={"native_target_id": target["id"], "checks": ["pods.health"]},
    )
    assert response.status_code == 502
    assert "malformed diagnostic data" in response.text
