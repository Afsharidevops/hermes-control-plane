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
BOT = {"Authorization": "Bearer test-bot"}
CREDENTIAL = {"Authorization": "Bearer test-credential-service"}
FP = "SHA256:" + "D" * 43


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(app) as c:
        yield c


def _cluster_and_target(client: TestClient) -> tuple[dict, dict]:
    env = client.post("/v1/environments", headers=ADMIN, json={"name": "Unified Verify", "risk_level": "HIGH"}).json()
    ssh = client.post(
        "/v1/internal/credential-refs/sync",
        headers=CREDENTIAL,
        json={"id": "cred_verifyssh123", "name": "verify-ssh", "kind": "ssh-key", "provider": "credential-service", "status": "configured", "metadata": {"fingerprint": "sha256:ssh"}},
    ).json()
    server = client.post(
        "/v1/servers",
        headers=ADMIN,
        json={"hostname": "verify-node-1", "environment_id": env["id"], "management_ip": "10.96.0.10", "ssh_port": 22, "ssh_user": "ubuntu", "host_fingerprint": FP, "connection_mode": "agent", "credential_ref": ssh["id"]},
    ).json()
    blueprint = client.post(
        "/v1/cluster-blueprints",
        headers=ADMIN,
        json={"name": "verify-blueprint", "provider": "k3s", "provider_version": "v1.35.6+k3s1", "kubernetes_version": "1.35.6", "network_plugin": "cilium", "hubble_enabled": True, "radar_enabled": False, "addon_versions": {"cilium": "1.19.4", "hubble": "1.19.4", "hermes-agent": "0.5.11-dev.5"}},
    ).json()
    profile = client.post(
        "/v1/cluster-profiles",
        headers=ADMIN,
        json={"name": "verify-profile", "environment_id": env["id"], "blueprint_id": blueprint["id"], "server_ids": [server["id"]]},
    ).json()
    cluster = client.post(
        "/v1/clusters",
        headers=ADMIN,
        json={"name": "verify-cluster", "environment_id": env["id"], "profile_id": profile["id"]},
    ).json()
    kube = client.post(
        "/v1/internal/credential-refs/sync",
        headers=CREDENTIAL,
        json={"id": "cred_verifykube12", "name": "verify-kube", "kind": "kubeconfig", "provider": "credential-service", "status": "configured", "metadata": {"sha256": "0" * 64}},
    ).json()
    target = client.post(
        "/v1/targets",
        headers=ADMIN,
        json={"name": "verify-k8s", "kind": "kubernetes", "environment_id": env["id"], "credential_ref": kube["id"], "connection_mode": "direct", "scope": {"namespace_allowlist": ["apps"], "cluster_read": True}},
    ).json()
    return cluster, target


def _diagnostic_result(check_ids: list[str], *, sensitive: bool = False) -> dict:
    checks = []
    for check_id in check_ids:
        evidence = {"collector": "live", "count": 1}
        if sensitive and not checks:
            evidence = {"env": "TOPSECRET"}
        checks.append({"id": check_id, "status": "PASS", "summary": f"{check_id} live probe passed", "evidence": evidence})
    return {
        "provider": "hermes-native-kubernetes-diagnostics",
        "observed_at": 1787169000,
        "overall_status": "PASS",
        "checks": checks,
        "summary": {"PASS": len(checks), "WARN": 0, "FAIL": 0, "SKIP": 0},
        "secret_data_requested": False,
        "mutation_commands_executed": False,
        "policy_scope": {"namespace_allowlist": ["apps"], "namespace_denylist": [], "cluster_read": True},
    }


def test_unified_verification_runs_live_collectors_persists_and_audits(client: TestClient, monkeypatch):
    cluster, target = _cluster_and_target(client)
    seen = []

    async def fake_post(path: str, payload: dict) -> dict:
        seen.append((path, payload))
        assert path == "/v1/diagnostics/run"
        return _diagnostic_result(payload["checks"])

    monkeypatch.setattr(kubernetes_broker, "post", fake_post)
    response = client.post(
        f"/v1/clusters/{cluster['id']}/verify",
        headers=ADMIN,
        json={"native_target_id": target["id"]},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    by_id = {item["id"]: item for item in body["checks"]}
    assert body["subject_type"] == "cluster"
    assert body["subject_id"] == cluster["id"]
    assert body["status"] == "WARN"  # Prometheus is not falsely inferred from metrics.k8s.io.
    assert by_id["api-server"]["status"] == "PASS"
    assert by_id["nodes"]["status"] == "PASS"
    assert by_id["etcd"]["status"] == "SKIP"
    assert by_id["hosts"]["status"] == "SKIP"
    assert by_id["radar"]["status"] == "SKIP"
    assert by_id["observability"]["status"] == "WARN"
    assert body["evidence"]["mutation_commands_executed"] is False
    assert seen and "security.rbac" in seen[0][1]["checks"]

    persisted = client.get(f"/v1/verifications?subject_id={cluster['id']}", headers=ADMIN)
    assert persisted.status_code == 200
    assert persisted.json()[0]["id"] == body["id"]

    audit = client.get("/v1/audit?limit=30", headers=ADMIN).json()
    assert any(row["event_type"] == "verification.active.executed" for row in audit)


def test_unified_verification_rejects_sensitive_broker_evidence(client: TestClient, monkeypatch):
    cluster, target = _cluster_and_target(client)

    async def fake_post(path: str, payload: dict) -> dict:
        return _diagnostic_result(payload["checks"], sensitive=True)

    monkeypatch.setattr(kubernetes_broker, "post", fake_post)
    response = client.post(
        f"/v1/clusters/{cluster['id']}/verify",
        headers=ADMIN,
        json={"native_target_id": target["id"], "checks": ["nodes"]},
    )
    assert response.status_code == 502
    assert "forbidden sensitive field" in response.text


def test_manually_recorded_all_skip_verification_stays_skip(client: TestClient):
    response = client.post(
        "/v1/verifications",
        headers=BOT,
        json={
            "subject_type": "cluster",
            "subject_id": "clu_future",
            "actor": "hermes-bot:verify",
            "observed_at": 1787169000,
            "checks": [{"id": "provider-runtime", "status": "SKIP", "summary": "No disposable provider target is configured.", "evidence": {"reason": "not-configured"}}],
            "evidence": {"source": "test"},
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "SKIP"
