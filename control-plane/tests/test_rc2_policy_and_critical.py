from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ["HERMES_CONTROL_ADMIN_TOKEN"] = "test-admin"
os.environ["HERMES_EXECUTION_HMAC_KEY"] = "ticket-key"
os.environ["HERMES_KUBERNETES_BROKER_TOKEN"] = "broker-key"
os.environ["HERMES_BOT_SERVICE_TOKEN"] = "test-bot"
os.environ["HERMES_APPROVAL_BOT_TOKEN"] = "test-approval"
os.environ["HERMES_APPROVAL_HMAC_KEY"] = "approval-hmac-key-0123456789abcdef0123456789abcdef"

from hermes_control_plane import db  # noqa: E402
from hermes_control_plane import main as cp  # noqa: E402

AUTH = {"Authorization": "Bearer test-admin"}
BOT_AUTH = {"Authorization": "Bearer test-bot"}
APPROVAL_AUTH = {"Authorization": "Bearer test-approval"}


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(cp.app) as c:
        yield c


def setup_target(client: TestClient) -> dict:
    env = client.post("/v1/environments", headers=AUTH, json={"name": "Production", "risk_level": "CRITICAL"}).json()
    cred = client.post("/v1/credential-refs", headers=AUTH, json={
        "name": "prod-kube", "kind": "kubeconfig", "provider": "local-file",
        "metadata": {"storage": "local-kubeconfig", "sha256": "a" * 64, "file": "cred_1111111111111111.yaml"},
    }).json()
    target = client.post("/v1/targets", headers=AUTH, json={
        "name": "prod-k8s", "kind": "kubernetes", "environment_id": env["id"],
        "credential_ref": cred["id"], "connection_mode": "direct",
    })
    assert target.status_code == 201, target.text
    return target.json()


def test_policy_generation_is_server_owned_persisted_and_bump_invalidates(client: TestClient, monkeypatch):
    target = setup_target(client)
    forced = client.post("/v1/changesets", headers=BOT_AUTH, json={
        "operation": "kubernetes.manifest.apply", "adapter": "kubernetes", "target_id": target["id"],
        "requested_by": "telegram:1", "source_channel": "hermes-bot", "policy_generation": 999,
        "parameters": {"manifest": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n"},
    })
    assert forced.status_code == 422

    created = client.post("/v1/changesets", headers=BOT_AUTH, json={
        "operation": "kubernetes.manifest.apply", "adapter": "kubernetes", "target_id": target["id"],
        "requested_by": "telegram:1", "source_channel": "hermes-bot",
        "parameters": {"manifest": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n"},
    }).json()
    assert created["policy_generation"] == 1
    assert created["plan"]["policy_generation"] == 1

    bumped = client.post("/v1/policy-generation/bump", headers=AUTH, json={"actor": "admin:release", "reason": "policy hardening"})
    assert bumped.status_code == 200
    assert bumped.json()["old_generation"] == 1
    assert bumped.json()["policy_generation"] == 2
    assert client.get(f"/v1/changesets/{created['id']}").json()["state"] == "STALE_POLICY"

    fresh = client.post("/v1/changesets", headers=BOT_AUTH, json={
        "operation": "kubernetes.manifest.apply", "adapter": "kubernetes", "target_id": target["id"],
        "requested_by": "telegram:1", "source_channel": "hermes-bot",
        "parameters": {"manifest": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo2\n"},
    }).json()
    assert fresh["policy_generation"] == 2
    assert fresh["plan_hash"] != created["plan_hash"]

    with db.connect() as conn:
        assert db.get_policy_generation(conn) == 2

    events = client.get("/v1/audit").json()
    bump = next(e for e in events if e["event_type"] == "policy.generation_bumped")
    assert bump["payload"]["old_generation"] == 1
    assert bump["payload"]["new_generation"] == 2
    assert bump["payload"]["reason"] == "policy hardening"


def test_stale_generation_rejected_during_preview_approval_and_execute(client: TestClient, monkeypatch):
    target = setup_target(client)

    async def fake_post(path, payload):
        if path == "/v1/preview":
            return {"summary": "ok", "kind": "kubernetes-manifest", "toolchain_binding_hash": "c" * 64}
        if path == "/v1/execute":
            return {"operation": payload["ticket"]["plan"]["operation"], "result": {"returncode": 0}}
        raise AssertionError(path)

    monkeypatch.setattr(cp.kubernetes_broker, "post", fake_post)
    chg = client.post("/v1/changesets", headers=BOT_AUTH, json={
        "operation": "kubernetes.manifest.apply", "adapter": "kubernetes", "target_id": target["id"],
        "requested_by": "telegram:1", "source_channel": "hermes-bot",
        "parameters": {"manifest": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n"},
    }).json()
    assert client.post(f"/v1/changesets/{chg['id']}/preview-live", headers=BOT_AUTH).status_code == 200
    assert client.post(f"/v1/changesets/{chg['id']}/request-approval", headers=BOT_AUTH).status_code == 200
    assert client.post(f"/v1/changesets/{chg['id']}/approve", headers=APPROVAL_AUTH, json={"approver": "approval-bot:1", "plan_hash": chg["plan_hash"]}).status_code == 201
    assert client.post("/v1/policy-generation/bump", headers=AUTH, json={"actor": "admin", "reason": "rotate policy"}).status_code == 200

    stale_approve = client.post(f"/v1/changesets/{chg['id']}/approve", headers=APPROVAL_AUTH, json={"approver": "approval-bot:2", "plan_hash": chg["plan_hash"]})
    assert stale_approve.status_code == 409
    monkeypatch.setenv("HERMES_EXECUTION_ENABLED", "true")
    stale_execute = client.post(f"/v1/changesets/{chg['id']}/execute", headers=BOT_AUTH, json={"actor": "telegram:1"})
    assert stale_execute.status_code == 409


def test_critical_requires_two_distinct_exact_hash_approvers(client: TestClient, monkeypatch):
    target = setup_target(client)

    async def fake_post(path, payload):
        if path == "/v1/preview":
            return {"summary": "critical preview", "kind": "kubernetes-manifest", "toolchain_binding_hash": "c" * 64}
        if path == "/v1/execute":
            return {"operation": "rbac.cluster-admin.apply", "result": {"returncode": 0}}
        raise AssertionError(path)

    monkeypatch.setattr(cp.kubernetes_broker, "post", fake_post)
    monkeypatch.setenv("HERMES_EXECUTION_ENABLED", "true")
    chg = client.post("/v1/changesets", headers=BOT_AUTH, json={
        "operation": "rbac.cluster-admin.apply", "adapter": "kubernetes", "target_id": target["id"],
        "requested_by": "telegram:requester", "source_channel": "hermes-bot",
        "parameters": {"manifest": "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: demo\n"},
    }).json()
    assert chg["risk"] == "CRITICAL"
    assert client.post(f"/v1/changesets/{chg['id']}/preview-live", headers=BOT_AUTH).status_code == 200
    assert client.post(f"/v1/changesets/{chg['id']}/request-approval", headers=BOT_AUTH).status_code == 200

    first = client.post(f"/v1/changesets/{chg['id']}/approve", headers=APPROVAL_AUTH, json={"approver": "approval-bot:1", "plan_hash": chg["plan_hash"]})
    assert first.status_code == 201
    assert first.json()["approval_count"] == 1
    assert first.json()["required_approvals"] == 2
    assert first.json()["changeset_state"] == "AWAITING_APPROVAL"

    duplicate = client.post(f"/v1/changesets/{chg['id']}/approve", headers=APPROVAL_AUTH, json={"approver": "approval-bot:1", "plan_hash": chg["plan_hash"]})
    assert duplicate.status_code == 409

    second = client.post(f"/v1/changesets/{chg['id']}/approve", headers=APPROVAL_AUTH, json={"approver": "approval-bot:2", "plan_hash": chg["plan_hash"]})
    assert second.status_code == 201
    assert second.json()["changeset_state"] == "APPROVED"
    assert second.json()["approval_count"] == 2

    executed = client.post(f"/v1/changesets/{chg['id']}/execute", headers=BOT_AUTH, json={"actor": "telegram:executor"})
    assert executed.status_code == 200, executed.text
    assert executed.json()["state"] == "EXECUTED"


def test_approval_is_integrity_bound_consumed_before_broker_network_failure(client: TestClient, monkeypatch):
    target = setup_target(client)

    async def fake_post(path, payload):
        if path == "/v1/preview":
            return {"summary": "ok", "kind": "kubernetes-manifest", "live_state_hash": "d" * 64}
        if path == "/v1/execute":
            from fastapi import HTTPException
            raise HTTPException(status_code=503, detail="injected broker network loss")
        raise AssertionError(path)

    monkeypatch.setattr(cp.kubernetes_broker, "post", fake_post)
    monkeypatch.setenv("HERMES_EXECUTION_ENABLED", "true")
    chg = client.post("/v1/changesets", headers=BOT_AUTH, json={
        "operation": "kubernetes.manifest.apply", "adapter": "kubernetes", "target_id": target["id"],
        "requested_by": "telegram:requester", "source_channel": "hermes-bot",
        "parameters": {"manifest": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: once\n"},
    }).json()
    assert client.post(f"/v1/changesets/{chg['id']}/preview-live", headers=BOT_AUTH).status_code == 200
    assert client.post(f"/v1/changesets/{chg['id']}/request-approval", headers=BOT_AUTH).status_code == 200
    approval = client.post(
        f"/v1/changesets/{chg['id']}/approve", headers=APPROVAL_AUTH,
        json={"approver": "approval-bot:once", "plan_hash": chg["plan_hash"]},
    )
    assert approval.status_code == 201, approval.text
    body = approval.json()
    assert len(body["nonce"]) >= 24
    assert len(body["mac"]) == 64
    assert body["policy_generation"] == chg["policy_generation"]

    failed = client.post(f"/v1/changesets/{chg['id']}/execute", headers=BOT_AUTH, json={"actor": "telegram:executor"})
    assert failed.status_code == 502
    approvals = client.get(f"/v1/changesets/{chg['id']}/approvals", headers=AUTH)
    assert approvals.status_code == 200
    assert approvals.json()[0]["status"] == "CONSUMED"
    assert approvals.json()[0]["consumed_at"] is not None

    retry = client.post(f"/v1/changesets/{chg['id']}/execute", headers=BOT_AUTH, json={"actor": "telegram:executor"})
    assert retry.status_code == 409
