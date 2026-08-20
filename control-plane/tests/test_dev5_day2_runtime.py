from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ["HERMES_CONTROL_ADMIN_TOKEN"] = "test-admin"
os.environ["HERMES_BOT_SERVICE_TOKEN"] = "test-bot"
os.environ["HERMES_APPROVAL_BOT_TOKEN"] = "test-approval"
os.environ["HERMES_APPROVAL_HMAC_KEY"] = "approval-hmac-key-0123456789abcdef0123456789abcdef"
os.environ["HERMES_EXECUTION_HMAC_KEY"] = "execution-ticket-key-0123456789abcdef0123456789abcdef"
os.environ["HERMES_CREDENTIAL_SERVICE_TOKEN"] = "test-credential-service"

from hermes_control_plane import db  # noqa: E402
from hermes_control_plane import kubernetes as kubernetes_broker  # noqa: E402
from hermes_control_plane.main import app  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin"}
BOT = {"Authorization": "Bearer test-bot"}
APPROVAL = {"Authorization": "Bearer test-approval"}
CREDENTIAL = {"Authorization": "Bearer test-credential-service"}
FP = "SHA256:" + "D" * 43


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(app) as c:
        yield c


def _cluster_and_target(client: TestClient) -> tuple[dict, dict]:
    env = client.post("/v1/environments", headers=ADMIN, json={"name": "Day2 Runtime", "risk_level": "HIGH"}).json()
    ssh = client.post(
        "/v1/internal/credential-refs/sync",
        headers=CREDENTIAL,
        json={"id": "cred_day2ssh12345", "name": "day2-ssh", "kind": "ssh-key", "provider": "credential-service", "status": "configured", "metadata": {"fingerprint": "sha256:ssh"}},
    ).json()
    server = client.post(
        "/v1/servers",
        headers=ADMIN,
        json={"hostname": "day2-node-1", "environment_id": env["id"], "management_ip": "10.92.0.10", "ssh_port": 22, "ssh_user": "ubuntu", "host_fingerprint": FP, "connection_mode": "agent", "credential_ref": ssh["id"]},
    ).json()
    blueprint = client.post(
        "/v1/cluster-blueprints",
        headers=ADMIN,
        json={"name": "day2-blueprint", "provider": "k3s", "provider_version": "v1.35.6+k3s1", "kubernetes_version": "1.35.6", "network_plugin": "cilium", "hubble_enabled": True, "radar_enabled": False, "addon_versions": {"cilium": "1.19.4", "hubble": "1.19.4", "hermes-agent": "0.5.11-dev.5"}},
    ).json()
    profile = client.post(
        "/v1/cluster-profiles",
        headers=ADMIN,
        json={"name": "day2-profile", "environment_id": env["id"], "blueprint_id": blueprint["id"], "server_ids": [server["id"]]},
    ).json()
    cluster = client.post(
        "/v1/clusters",
        headers=ADMIN,
        json={"name": "day2-cluster", "environment_id": env["id"], "profile_id": profile["id"]},
    ).json()
    with db.connect() as conn:
        conn.execute("UPDATE clusters SET state='READY' WHERE id=?", (cluster["id"],))
        conn.commit()
    kube = client.post(
        "/v1/internal/credential-refs/sync",
        headers=CREDENTIAL,
        json={"id": "cred_day2kube1234", "name": "day2-kube", "kind": "kubeconfig", "provider": "credential-service", "status": "configured", "metadata": {"sha256": "0" * 64}},
    ).json()
    target = client.post(
        "/v1/targets",
        headers=ADMIN,
        json={"name": "day2-k8s", "kind": "kubernetes", "environment_id": env["id"], "credential_ref": kube["id"], "connection_mode": "direct", "scope": {"namespace_allowlist": ["apps"], "cluster_read": True}},
    ).json()
    return cluster, target


def _approve(client: TestClient, changeset: dict) -> None:
    requested = client.post(f"/v1/changesets/{changeset['id']}/request-approval", headers=BOT)
    assert requested.status_code == 200, requested.text
    approved = client.post(
        f"/v1/changesets/{changeset['id']}/approve",
        headers=APPROVAL,
        json={"approver": "approval-bot:day2", "plan_hash": changeset["plan_hash"]},
    )
    assert approved.status_code == 201, approved.text


def test_day2_cordon_is_bound_to_kubernetes_target_and_executes_with_active_verification(client: TestClient, monkeypatch):
    cluster, target = _cluster_and_target(client)
    seen = []

    async def fake_post(path: str, payload: dict) -> dict:
        seen.append((path, payload))
        if path == "/v1/day2/preview":
            return {
                "kind": "kubernetes-day2-node-preview",
                "operation": "cluster.node.cordon",
                "before": {"node": "day2-node-1", "uid": "node-uid", "unschedulable": False},
                "desired": {"node": "day2-node-1", "uid": "node-uid", "unschedulable": True},
                "preconditions": {"node_state_hash": "a" * 64},
                "secret_output_suppressed": True,
            }
        assert path == "/v1/day2/execute"
        return {
            "schema_version": 1,
            "operation": "cluster.node.cordon",
            "typed_plan_hash": payload["ticket"]["plan"]["parameters"]["typed_plan"]["plan_hash"],
            "target_snapshot_hash": payload["ticket"]["plan"]["parameters"]["typed_plan"]["targets"][1]["snapshot_hash"],
            "result": {"command": {"returncode": 0}},
            "verification": {
                "observed_at": 1787162000,
                "checks": [{"id": "node-unschedulable", "status": "PASS", "summary": "node is cordoned", "evidence": {"node": "day2-node-1", "unschedulable": True}}],
                "evidence": {"source": "kubernetes-broker-active-verification", "arbitrary_shell": False, "raw_credentials_returned": False},
            },
        }

    monkeypatch.setattr(kubernetes_broker, "post", fake_post)
    planned = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={
            "requested_by": "hermes-bot:day2",
            "source_channel": "hermes-bot",
            "domain": "day2",
            "operation": "cluster.node.cordon",
            "target_id": cluster["id"],
            "parameters": {"native_target_id": target["id"], "node": "day2-node-1"},
        },
    )
    assert planned.status_code == 201, planned.text
    body = planned.json()
    assert body["operation_job"]["executor"] == "kubernetes-broker"
    assert body["operation_plan"]["plan"]["targets"][1]["id"] == target["id"]
    assert body["operation_plan"]["plan"]["runtime_preview"]["preconditions"]["node_state_hash"] == "a" * 64
    _approve(client, body["changeset"])
    authorized = client.post(f"/v1/operation-jobs/{body['operation_job']['id']}/authorize", headers=BOT)
    assert authorized.status_code == 200, authorized.text
    auth = authorized.json()
    executed = client.post(
        f"/v1/operation-jobs/{body['operation_job']['id']}/execute",
        headers=BOT,
        json={"execution_ticket": auth["execution_ticket"], "signature": auth["signature"], "actor": "hermes-bot:day2"},
    )
    assert executed.status_code == 200, executed.text
    result = executed.json()
    assert result["operation_job"]["state"] == "SUCCEEDED"
    assert result["verification"]["status"] == "PASS"
    assert [item[0] for item in seen] == ["/v1/day2/preview", "/v1/day2/execute"]
    changeset = client.get(f"/v1/changesets/{body['changeset']['id']}").json()
    assert changeset["state"] == "EXECUTED"
    verifications = client.get(f"/v1/verifications?subject_id={cluster['id']}", headers=ADMIN).json()
    assert verifications[0]["operation_plan_id"] == body["operation_plan"]["id"]
    assert verifications[0]["checks"][0]["id"] == "node-unschedulable"


def test_day2_runtime_rejects_missing_native_target_and_non_runtime_operation(client: TestClient):
    cluster, _ = _cluster_and_target(client)
    missing = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={"requested_by": "hermes-bot:day2", "source_channel": "hermes-bot", "domain": "day2", "operation": "cluster.workload.scale", "target_id": cluster["id"], "parameters": {"kind": "deployment", "name": "api", "namespace": "apps", "replicas": 3}},
    )
    assert missing.status_code == 422
    assert "native_target_id" in missing.text

    provider_only = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={"requested_by": "hermes-bot:day2", "source_channel": "hermes-bot", "domain": "day2", "operation": "cluster.worker.add", "target_id": cluster["id"], "parameters": {"server_id": "srv_future"}},
    )
    assert provider_only.status_code == 201, provider_only.text
    assert provider_only.json()["operation_job"]["executor"] == "cluster-provider-worker"
