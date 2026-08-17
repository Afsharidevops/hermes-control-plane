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
    env = client.post("/v1/environments", headers=AUTH, json={"name": "Production", "risk_level": "HIGH"}).json()
    cred = client.post("/v1/credential-refs", headers=AUTH, json={"name": "prod-kube", "kind": "kubeconfig", "provider": "local-file", "metadata": {"storage": "local-kubeconfig", "sha256": "a" * 64, "file": "cred_1111111111111111.yaml"}}).json()
    target = client.post("/v1/targets", headers=AUTH, json={"name": "prod-k8s", "kind": "kubernetes", "environment_id": env["id"], "credential_ref": cred["id"], "connection_mode": "direct"})
    assert target.status_code == 201, target.text
    return target.json()


def test_live_preview_binds_target_snapshot(client: TestClient, monkeypatch):
    target = setup_target(client)

    async def fake_post(path, payload):
        assert path == "/v1/preview"
        assert payload["plan"]["target_snapshot"]["credential_snapshot"]["metadata"]["sha256"] == "a" * 64
        return {"summary": "server dry-run passed", "kind": "kubernetes-manifest", "resources": []}

    monkeypatch.setattr(cp.kubernetes_broker, "post", fake_post)
    chg = client.post("/v1/changesets", headers=BOT_AUTH, json={
        "operation": "kubernetes.manifest.apply", "adapter": "kubernetes", "target_id": target["id"],
        "requested_by": "ui:requester", "parameters": {"namespace": "default", "manifest": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n"}
    }).json()
    assert chg["plan"]["schema_version"] == 2
    preview = client.post(f"/v1/changesets/{chg['id']}/preview-live", headers=BOT_AUTH)
    assert preview.status_code == 200, preview.text
    assert preview.json()["preview"]["source"] == "kubernetes-broker"


def test_target_drift_invalidates_live_preview(client: TestClient, monkeypatch):
    target = setup_target(client)
    chg = client.post("/v1/changesets", headers=BOT_AUTH, json={
        "operation": "kubernetes.manifest.apply", "adapter": "kubernetes", "target_id": target["id"],
        "requested_by": "ui:requester", "parameters": {"manifest": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n"}
    }).json()
    update = client.patch(f"/v1/targets/{target['id']}", headers=AUTH, json={"scope": {"namespace_allowlist": ["apps"]}})
    assert update.status_code == 200
    preview = client.post(f"/v1/changesets/{chg['id']}/preview-live", headers=BOT_AUTH)
    assert preview.status_code == 409


def test_approved_exact_plan_executes_with_signed_ticket(client: TestClient, monkeypatch):
    target = setup_target(client)
    calls = []

    async def fake_post(path, payload):
        calls.append((path, payload))
        if path == "/v1/preview":
            return {"summary": "server dry-run passed", "kind": "kubernetes-manifest", "toolchain_binding_hash": "c" * 64}
        if path == "/v1/execute":
            assert payload["ticket"]["plan_hash"]
            assert payload["ticket"]["preconditions"]["toolchain_binding_hash"] == "c" * 64
            assert len(payload["signature"]) == 64
            return {"operation": "kubernetes.manifest.apply", "result": {"returncode": 0, "output": "configmap/demo"}}
        raise AssertionError(path)

    monkeypatch.setattr(cp.kubernetes_broker, "post", fake_post)
    monkeypatch.setenv("HERMES_EXECUTION_ENABLED", "true")
    chg = client.post("/v1/changesets", headers=BOT_AUTH, json={
        "operation": "kubernetes.manifest.apply", "adapter": "kubernetes", "target_id": target["id"],
        "requested_by": "ui:requester", "parameters": {"manifest": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n"}
    }).json()
    preview = client.post(f"/v1/changesets/{chg['id']}/preview-live", headers=BOT_AUTH)
    assert preview.status_code == 200
    assert preview.json()["state"] == "PREVIEWED"
    assert preview.json()["executable"] is False

    assert client.post(f"/v1/changesets/{chg['id']}/request-approval", headers=BOT_AUTH).status_code == 200

    approval = client.post(
        f"/v1/changesets/{chg['id']}/approve",
        headers=APPROVAL_AUTH,
        json={"approver": "ui:approver", "plan_hash": chg["plan_hash"]},
    )
    assert approval.status_code == 201

    approved = client.get(f"/v1/changesets/{chg['id']}").json()
    assert approved["state"] == "APPROVED"
    assert approved["executable"] is True
    executed = client.post(f"/v1/changesets/{chg['id']}/execute", headers=BOT_AUTH, json={"actor": "ui:executor"})
    assert executed.status_code == 200, executed.text
    assert executed.json()["state"] == "EXECUTED"
    assert calls[-1][0] == "/v1/execute"


def test_live_preview_policy_denial_is_terminal(client: TestClient, monkeypatch):
    from fastapi import HTTPException

    target = setup_target(client)

    async def fake_post(path, payload):
        assert path == "/v1/preview"
        raise HTTPException(403, "Secret is denied by the beta.1 safety floor")

    monkeypatch.setattr(cp.kubernetes_broker, "post", fake_post)
    chg = client.post("/v1/changesets", headers=BOT_AUTH, json={
        "operation": "kubernetes.manifest.apply", "adapter": "kubernetes", "target_id": target["id"],
        "requested_by": "ui:requester", "parameters": {"namespace": "default", "manifest": "apiVersion: v1\nkind: Secret\nmetadata:\n  name: nope\n"}
    }).json()
    preview = client.post(f"/v1/changesets/{chg['id']}/preview-live", headers=BOT_AUTH)
    assert preview.status_code == 403
    assert preview.json()["detail"] == "Secret is denied by the beta.1 safety floor"
    monkeypatch.setenv("HERMES_EXECUTION_ENABLED", "true")
    stored = client.get(f"/v1/changesets/{chg['id']}").json()
    assert stored["state"] == "POLICY_DENIED"
    assert stored["executable"] is False
    assert stored["preview"]["details"]["status_code"] == 403
    audit = client.get("/v1/audit").json()
    assert any(x["event_type"] == "changeset.policy_denied" and x["subject_id"] == chg["id"] for x in audit)


def test_live_preview_validation_failure_is_terminal(client: TestClient, monkeypatch):
    from fastapi import HTTPException

    target = setup_target(client)

    async def fake_post(path, payload):
        raise HTTPException(422, "invalid Helm chart reference")

    monkeypatch.setattr(cp.kubernetes_broker, "post", fake_post)
    chg = client.post("/v1/changesets", headers=BOT_AUTH, json={
        "operation": "helm.install", "adapter": "helm", "target_id": target["id"],
        "requested_by": "ui:requester", "parameters": {"release": "demo", "chart": "-bad", "namespace": "default"}
    }).json()
    preview = client.post(f"/v1/changesets/{chg['id']}/preview-live", headers=BOT_AUTH)
    assert preview.status_code == 422
    stored = client.get(f"/v1/changesets/{chg['id']}").json()
    assert stored["state"] == "PREVIEW_FAILED"
    assert stored["preview"]["details"]["detail"] == "invalid Helm chart reference"



def test_generate_kubernetes_rollback_plan_from_execution_before_state(client: TestClient, monkeypatch):
    target = setup_target(client)
    old_manifest = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n  namespace: default\ndata:\n  value: one\n"

    async def fake_post(path, payload):
        if path == "/v1/preview":
            return {"summary": "preview", "kind": "kubernetes-manifest", "live_state_hash": "b" * 64}
        if path == "/v1/execute":
            return {
                "operation": "kubernetes.manifest.apply",
                "before_state": {
                    "hash": "b" * 64,
                    "resources": [{
                        "resource": {"apiVersion": "v1", "kind": "ConfigMap", "name": "demo", "namespace": "default"},
                        "exists": True,
                        "manifest": old_manifest,
                    }],
                },
                "result": {"returncode": 0, "output": "configmap/demo"},
                "verification": {"converged": True},
            }
        raise AssertionError(path)

    monkeypatch.setattr(cp.kubernetes_broker, "post", fake_post)
    monkeypatch.setenv("HERMES_EXECUTION_ENABLED", "true")
    chg = client.post("/v1/changesets", headers=BOT_AUTH, json={
        "operation": "kubernetes.manifest.apply",
        "adapter": "kubernetes",
        "target_id": target["id"],
        "requested_by": "ui:requester",
        "parameters": {"namespace": "default", "manifest": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n  namespace: default\ndata:\n  value: two\n"},
    }).json()
    assert client.post(f"/v1/changesets/{chg['id']}/preview-live", headers=BOT_AUTH).status_code == 200
    assert client.post(f"/v1/changesets/{chg['id']}/request-approval", headers=BOT_AUTH).status_code == 200
    assert client.post(f"/v1/changesets/{chg['id']}/approve", headers=APPROVAL_AUTH, json={"approver": "ui:approver", "plan_hash": chg["plan_hash"]}).status_code == 201
    executed = client.post(f"/v1/changesets/{chg['id']}/execute", headers=BOT_AUTH, json={"actor": "ui:executor"})
    assert executed.status_code == 200

    rollback = client.post(
        f"/v1/changesets/{chg['id']}/rollback-plan",
        headers=BOT_AUTH,
        json={"requested_by": "ui:requester", "source_channel": "hermes-bot"},
    )
    assert rollback.status_code == 201, rollback.text
    body = rollback.json()
    assert body["operation"] == "kubernetes.manifest.rollback"
    assert body["state"] == "PLANNED"
    assert body["parameters"]["source_changeset_id"] == chg["id"]
    assert body["parameters"]["actions"][0]["action"] == "apply"
    assert "value: one" in body["parameters"]["actions"][0]["manifest"]


def test_helm_uninstall_is_high_risk():
    from hermes_control_plane.risk import classify
    assert classify("helm.uninstall") == "HIGH"


def test_ui_admin_cannot_create_kubernetes_mutation(client: TestClient):
    target = setup_target(client)
    response = client.post("/v1/changesets", headers=AUTH, json={
        "operation": "kubernetes.manifest.apply",
        "adapter": "kubernetes",
        "target_id": target["id"],
        "requested_by": "ui:admin",
        "source_channel": "ui",
        "parameters": {"namespace": "default", "manifest": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: denied\n"},
    })
    assert response.status_code == 403


def test_bot_token_cannot_approve_its_own_infra_changeset(client: TestClient, monkeypatch):
    target = setup_target(client)

    async def fake_post(path, payload):
        if path == "/v1/preview":
            return {"summary": "preview ok", "kind": "kubernetes-manifest"}
        raise AssertionError(path)

    monkeypatch.setattr(cp.kubernetes_broker, "post", fake_post)
    chg = client.post("/v1/changesets", headers=BOT_AUTH, json={
        "operation": "kubernetes.manifest.apply",
        "adapter": "kubernetes",
        "target_id": target["id"],
        "requested_by": "telegram:123",
        "source_channel": "hermes-bot",
        "parameters": {"namespace": "default", "manifest": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n"},
    }).json()
    assert client.post(f"/v1/changesets/{chg['id']}/preview-live", headers=BOT_AUTH).status_code == 200
    assert client.post(f"/v1/changesets/{chg['id']}/request-approval", headers=BOT_AUTH).status_code == 200
    denied = client.post(
        f"/v1/changesets/{chg['id']}/approve",
        headers=BOT_AUTH,
        json={"approver": "approval-bot:1", "plan_hash": chg["plan_hash"]},
    )
    assert denied.status_code == 403
    approved = client.post(
        f"/v1/changesets/{chg['id']}/approve",
        headers=APPROVAL_AUTH,
        json={"approver": "approval-bot:1", "plan_hash": chg["plan_hash"]},
    )
    assert approved.status_code == 201

def test_admin_cannot_preview_or_execute_bot_mutation(client: TestClient, monkeypatch):
    target = setup_target(client)

    async def fake_post(path, payload):
        if path == "/v1/preview":
            return {"summary": "preview ok", "kind": "kubernetes-manifest"}
        if path == "/v1/execute":
            return {"operation": "kubernetes.manifest.apply", "result": {"returncode": 0}}
        raise AssertionError(path)

    monkeypatch.setattr(cp.kubernetes_broker, "post", fake_post)
    monkeypatch.setenv("HERMES_EXECUTION_ENABLED", "true")
    chg = client.post("/v1/changesets", headers=BOT_AUTH, json={
        "operation": "kubernetes.manifest.apply",
        "adapter": "kubernetes",
        "target_id": target["id"],
        "requested_by": "telegram:123",
        "source_channel": "hermes-bot",
        "parameters": {"namespace": "default", "manifest": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n"},
    }).json()

    assert client.post(f"/v1/changesets/{chg['id']}/preview-live", headers=AUTH).status_code == 403
    assert client.post(f"/v1/changesets/{chg['id']}/preview-live", headers=BOT_AUTH).status_code == 200
    assert client.post(f"/v1/changesets/{chg['id']}/request-approval", headers=BOT_AUTH).status_code == 200
    assert client.post(
        f"/v1/changesets/{chg['id']}/approve",
        headers=APPROVAL_AUTH,
        json={"approver": "approval-bot:1", "plan_hash": chg["plan_hash"]},
    ).status_code == 201
    denied = client.post(f"/v1/changesets/{chg['id']}/execute", headers=AUTH, json={"actor": "ui:admin"})
    assert denied.status_code == 403


def test_ui_contains_no_kubernetes_or_helm_mutation_forms(client: TestClient):
    html = client.get("/ui").text
    assert "Bot-managed changes" in html
    assert "Kubernetes manifest plan" not in html
    assert "Helm plan" not in html
    assert "Request approval" not in html
    assert "Approve exact hash" not in html
