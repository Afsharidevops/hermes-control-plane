from __future__ import annotations

import json
import os
from contextlib import closing
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
from hermes_control_plane import provider_worker  # noqa: E402
from hermes_control_plane.main import app  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin"}
BOT = {"Authorization": "Bearer test-bot"}
APPROVAL = {"Authorization": "Bearer test-approval"}
CREDENTIAL = {"Authorization": "Bearer test-credential-service"}
FP = "SHA256:" + "E" * 43


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(app) as c:
        yield c


def _credential(client: TestClient, suffix: str) -> dict:
    return client.post(
        "/v1/internal/credential-refs/sync",
        headers=CREDENTIAL,
        json={
            "id": f"cred_{suffix:0<16}"[:21],
            "name": f"ssh-{suffix}",
            "kind": "ssh-key",
            "provider": "credential-service",
            "status": "configured",
            "metadata": {"fingerprint": "sha256:" + "a" * 64},
        },
    ).json()


def _server(client: TestClient, env_id: str, cred_id: str, name: str, ip: str) -> dict:
    server = client.post(
        "/v1/servers",
        headers=ADMIN,
        json={
            "hostname": name,
            "environment_id": env_id,
            "management_ip": ip,
            "ssh_port": 22,
            "ssh_user": "ubuntu",
            "host_fingerprint": FP,
            "connection_mode": "direct",
            "credential_ref": cred_id,
        },
    ).json()
    with closing(db.connect()) as conn:
        conn.execute("UPDATE servers SET preflight_status='PASS' WHERE id=?", (server["id"],))
        conn.commit()
    return client.get(f"/v1/servers/{server['id']}", headers=ADMIN).json()


def _artifact(client: TestClient, *, name: str, component: str, component_name: str, version: str, index: int) -> dict:
    artifact = client.post(
        "/v1/artifact-mirror/items",
        headers=ADMIN,
        json={
            "name": name,
            "kind": "helm-chart" if component == "addon" else "package",
            "source": f"https://source.example/{name}",
            "destination": f"file:///srv/hermes-mirror/{name}",
            "version": version,
            "digest": "sha256:" + format(index, "064x"),
            "labels": {
                "blueprint_component": component,
                "blueprint_name": component_name,
                "dependency_key": name,
            },
        },
    ).json()
    verification = {
        "verification_id": f"ver_{artifact['id'][4:]}",
        "status": "PASS",
        "sync_state": "MIRRORED",
        "checks": [{"id": "destination-digest", "status": "PASS"}],
        "observed_at": 1770000000,
    }
    with closing(db.connect()) as conn:
        conn.execute("UPDATE artifact_mirror_items SET verification_json=? WHERE id=?", (json.dumps(verification, sort_keys=True), artifact["id"]))
        conn.commit()
    return artifact


def _cluster_fixture(client: TestClient, *, ready: bool) -> tuple[dict, dict, dict]:
    env = client.post("/v1/environments", headers=ADMIN, json={"name": "Batch B", "risk_level": "HIGH"}).json()
    cred1 = _credential(client, "batchbcp")
    cred2 = _credential(client, "batchbnew")
    cp = _server(client, env["id"], cred1["id"], "batchb-cp01", "10.99.0.10")
    future = _server(client, env["id"], cred2["id"], "batchb-worker02", "10.99.0.20")

    artifacts = [
        _artifact(client, name="k3s-provider", component="provider", component_name="k3s", version="v1.35.6+k3s1", index=1),
        _artifact(client, name="kubernetes", component="kubernetes", component_name="kubernetes", version="1.35.6", index=2),
        _artifact(client, name="cilium", component="addon", component_name="cilium", version="1.19.4", index=3),
        _artifact(client, name="agent", component="addon", component_name="hermes-agent", version="0.5.11-dev.5", index=4),
    ]
    blueprint = client.post(
        "/v1/cluster-blueprints",
        headers=ADMIN,
        json={
            "name": "batch-b-blueprint",
            "provider": "k3s",
            "provider_version": "v1.35.6+k3s1",
            "kubernetes_version": "1.35.6",
            "network_plugin": "cilium",
            "hubble_enabled": False,
            "radar_enabled": False,
            "addon_versions": {"cilium": "1.19.4", "hermes-agent": "0.5.11-dev.5"},
            "artifact_dependencies": [item["id"] for item in artifacts],
        },
    ).json()
    profile = client.post(
        "/v1/cluster-profiles",
        headers=ADMIN,
        json={"name": "batch-b-profile", "environment_id": env["id"], "blueprint_id": blueprint["id"], "server_ids": [cp["id"]]},
    ).json()
    role = client.post(
        "/v1/node-roles",
        headers=ADMIN,
        json={"profile_id": profile["id"], "role": "control-plane-worker", "server_ids": [cp["id"]]},
    )
    assert role.status_code == 201, role.text
    cluster = client.post(
        "/v1/clusters",
        headers=ADMIN,
        json={"name": "batch-b-cluster", "environment_id": env["id"], "profile_id": profile["id"]},
    ).json()
    if ready:
        with closing(db.connect()) as conn:
            conn.execute("UPDATE clusters SET state='READY' WHERE id=?", (cluster["id"],))
            conn.commit()
        cluster = client.get(f"/v1/clusters/{cluster['id']}", headers=ADMIN).json()
    return cluster, future, blueprint


def _approve(client: TestClient, changeset: dict, approver: str = "approval-bot:batch-b") -> None:
    assert client.post(f"/v1/changesets/{changeset['id']}/request-approval", headers=BOT).status_code == 200
    approved = client.post(
        f"/v1/changesets/{changeset['id']}/approve",
        headers=APPROVAL,
        json={"approver": approver, "plan_hash": changeset["plan_hash"]},
    )
    assert approved.status_code == 201, approved.text


def _provider_result(operation: str) -> dict:
    return {
        "state": "SUCCEEDED",
        "operation": operation,
        "verification": {
            "checks": [
                {"id": "provider-active-verify", "status": "PASS", "summary": "fixed provider verification passed", "evidence": {"host_count": 1}},
                {"id": "offline-artifact-binding", "status": "PASS", "summary": "offline binding consumed", "evidence": {"manifest_hash": "a" * 64}},
            ],
            "evidence": {"arbitrary_shell": False, "arbitrary_ssh_command": False, "raw_credentials_returned": False},
            "observed_at": 1770000001,
        },
    }


def test_provisioning_run_uses_one_signed_coordinator_job_and_trusted_runtime(client: TestClient, monkeypatch):
    cluster, _, _ = _cluster_fixture(client, ready=False)
    seen = []

    async def fake_post(path: str, payload: dict) -> dict:
        seen.append(path)
        assert path == "/v1/provider/execute"
        return _provider_result("cluster.provision.apply")

    monkeypatch.setattr(provider_worker, "post", fake_post)
    response = client.post(
        f"/v1/clusters/{cluster['id']}/provisioning-runs",
        headers=BOT,
        json={"requested_by": "hermes-bot:batch-b", "source_channel": "hermes-bot"},
    )
    assert response.status_code == 201, response.text
    run = response.json()
    assert len(run["provider_job_ids"]) == 1
    assert run["plan"]["artifact_supply"]["provisioner_rewrite_applied"] is True
    assert run["plan"]["provider_payload"]["provisioner_rewrite_applied"] is True
    _approve(client, run["changeset"])
    auth = client.post(f"/v1/provider-jobs/{run['provider_job_ids'][0]}/authorize", headers=BOT)
    assert auth.status_code == 200, auth.text
    assert auth.json()["execution_ticket"]["preconditions"]["executor"] == "cluster-provider-worker"
    executed = client.post(
        f"/v1/provider-jobs/{run['provider_job_ids'][0]}/execute",
        headers=BOT,
        json={"execution_ticket": auth.json()["execution_ticket"], "signature": auth.json()["signature"], "actor": "hermes-bot:batch-b"},
    )
    assert executed.status_code == 200, executed.text
    assert executed.json()["provider_job"]["state"] == "SUCCEEDED"
    assert executed.json()["verification"]["status"] == "PASS"
    assert seen == ["/v1/provider/execute"]
    assert client.get(f"/v1/clusters/{cluster['id']}", headers=ADMIN).json()["state"] == "READY"


def test_worker_add_is_typed_previewed_and_runtime_executable(client: TestClient, monkeypatch):
    cluster, future, _ = _cluster_fixture(client, ready=True)
    seen = []

    async def fake_post(path: str, payload: dict) -> dict:
        seen.append(path)
        if path == "/v1/provider/preview":
            typed = payload["changeset_plan"]["parameters"]["typed_plan"]
            assert typed["artifact_supply"]["provisioner_rewrite_applied"] is True
            return {
                "kind": "ProviderRuntimePreview",
                "operation": typed["operation"],
                "provider": "k3s",
                "preconditions": {"typed_plan_hash": typed["plan_hash"]},
                "secret_output_suppressed": True,
                "arbitrary_shell": False,
                "arbitrary_ssh_command": False,
                "credential_material_returned": False,
            }
        assert path == "/v1/provider/execute"
        return _provider_result("cluster.worker.add")

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={
            "requested_by": "hermes-bot:batch-b",
            "source_channel": "hermes-bot",
            "domain": "day2",
            "operation": "cluster.worker.add",
            "target_id": cluster["id"],
            "parameters": {"server_id": future["id"]},
        },
    )
    assert planned.status_code == 201, planned.text
    body = planned.json()
    assert body["operation_job"]["executor"] == "cluster-provider-worker"
    assert body["operation_plan"]["plan"]["runtime_preview"]["arbitrary_shell"] is False
    assert body["changeset"]["risk"] == "HIGH"
    assert body["changeset"]["approval_required"] is True
    _approve(client, body["changeset"])
    auth = client.post(f"/v1/operation-jobs/{body['operation_job']['id']}/authorize", headers=BOT).json()
    executed = client.post(
        f"/v1/operation-jobs/{body['operation_job']['id']}/execute",
        headers=BOT,
        json={"execution_ticket": auth["execution_ticket"], "signature": auth["signature"], "actor": "hermes-bot:batch-b"},
    )
    assert executed.status_code == 200, executed.text
    assert executed.json()["operation_job"]["state"] == "SUCCEEDED"
    assert executed.json()["verification"]["status"] == "PASS"
    assert seen == ["/v1/provider/preview", "/v1/provider/execute"]


def test_direct_etcd_restore_is_provider_runtime_and_critical(client: TestClient, monkeypatch):
    cluster, _, _ = _cluster_fixture(client, ready=True)

    async def fake_post(path: str, payload: dict) -> dict:
        assert path == "/v1/provider/preview"
        return {
            "kind": "ProviderRuntimePreview",
            "operation": "cluster.etcd.restore",
            "provider": "k3s",
            "preconditions": {"typed_plan_hash": payload["changeset_plan"]["parameters"]["typed_plan"]["plan_hash"]},
            "secret_output_suppressed": True,
            "arbitrary_shell": False,
            "arbitrary_ssh_command": False,
            "credential_material_returned": False,
        }

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={
            "requested_by": "hermes-bot:batch-b",
            "source_channel": "hermes-bot",
            "domain": "day2",
            "operation": "cluster.etcd.restore",
            "target_id": cluster["id"],
            "parameters": {"snapshot_reference": "before-upgrade-20260821"},
        },
    )
    assert planned.status_code == 201, planned.text
    body = planned.json()
    assert body["operation_job"]["executor"] == "cluster-provider-worker"
    assert body["changeset"]["risk"] == "CRITICAL"
    assert body["changeset"]["approval_required"] is True

    assert client.post(f"/v1/changesets/{body['changeset']['id']}/request-approval", headers=BOT).status_code == 200
    first = client.post(
        f"/v1/changesets/{body['changeset']['id']}/approve",
        headers=APPROVAL,
        json={"approver": "approval-bot:restore-a", "plan_hash": body["changeset"]["plan_hash"]},
    )
    assert first.status_code == 201, first.text
    assert first.json()["required_approvals"] == 2
    assert first.json()["changeset_state"] == "AWAITING_APPROVAL"
    blocked = client.post(f"/v1/operation-jobs/{body['operation_job']['id']}/authorize", headers=BOT)
    assert blocked.status_code == 409

    second = client.post(
        f"/v1/changesets/{body['changeset']['id']}/approve",
        headers=APPROVAL,
        json={"approver": "approval-bot:restore-b", "plan_hash": body["changeset"]["plan_hash"]},
    )
    assert second.status_code == 201, second.text
    assert second.json()["required_approvals"] == 2
    assert second.json()["changeset_state"] == "APPROVED"
