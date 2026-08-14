from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ["HERMES_CONTROL_ADMIN_TOKEN"] = "test-admin"
os.environ["HERMES_EXECUTION_HMAC_KEY"] = "ticket-key"
os.environ["HERMES_KUBERNETES_BROKER_TOKEN"] = "broker-key"

from hermes_control_plane import db  # noqa: E402
from hermes_control_plane import main as cp  # noqa: E402

AUTH = {"Authorization": "Bearer test-admin"}


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
    chg = client.post("/v1/changesets", headers=AUTH, json={
        "operation": "kubernetes.manifest.apply", "adapter": "kubernetes", "target_id": target["id"],
        "requested_by": "ui:requester", "parameters": {"namespace": "default", "manifest": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n"}
    }).json()
    assert chg["plan"]["schema_version"] == 2
    preview = client.post(f"/v1/changesets/{chg['id']}/preview-live", headers=AUTH)
    assert preview.status_code == 200, preview.text
    assert preview.json()["preview"]["source"] == "kubernetes-broker"


def test_target_drift_invalidates_live_preview(client: TestClient, monkeypatch):
    target = setup_target(client)
    chg = client.post("/v1/changesets", headers=AUTH, json={
        "operation": "kubernetes.manifest.apply", "adapter": "kubernetes", "target_id": target["id"],
        "requested_by": "ui:requester", "parameters": {"manifest": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n"}
    }).json()
    update = client.patch(f"/v1/targets/{target['id']}", headers=AUTH, json={"scope": {"namespace_allowlist": ["apps"]}})
    assert update.status_code == 200
    preview = client.post(f"/v1/changesets/{chg['id']}/preview-live", headers=AUTH)
    assert preview.status_code == 409


def test_approved_exact_plan_executes_with_signed_ticket(client: TestClient, monkeypatch):
    target = setup_target(client)
    calls = []

    async def fake_post(path, payload):
        calls.append((path, payload))
        if path == "/v1/preview":
            return {"summary": "server dry-run passed", "kind": "kubernetes-manifest"}
        if path == "/v1/execute":
            assert payload["ticket"]["plan_hash"]
            assert len(payload["signature"]) == 64
            return {"operation": "kubernetes.manifest.apply", "result": {"returncode": 0, "output": "configmap/demo"}}
        raise AssertionError(path)

    monkeypatch.setattr(cp.kubernetes_broker, "post", fake_post)
    monkeypatch.setenv("HERMES_EXECUTION_ENABLED", "true")
    chg = client.post("/v1/changesets", headers=AUTH, json={
        "operation": "kubernetes.manifest.apply", "adapter": "kubernetes", "target_id": target["id"],
        "requested_by": "ui:requester", "parameters": {"manifest": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n"}
    }).json()
    assert client.post(f"/v1/changesets/{chg['id']}/preview-live", headers=AUTH).status_code == 200
    assert client.post(f"/v1/changesets/{chg['id']}/request-approval", headers=AUTH).status_code == 200
    approval = client.post(f"/v1/changesets/{chg['id']}/approve", headers=AUTH, json={"approver": "ui:approver", "plan_hash": chg["plan_hash"]})
    assert approval.status_code == 201
    executed = client.post(f"/v1/changesets/{chg['id']}/execute", headers=AUTH, json={"actor": "ui:executor"})
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
    chg = client.post("/v1/changesets", headers=AUTH, json={
        "operation": "kubernetes.manifest.apply", "adapter": "kubernetes", "target_id": target["id"],
        "requested_by": "ui:requester", "parameters": {"namespace": "default", "manifest": "apiVersion: v1\nkind: Secret\nmetadata:\n  name: nope\n"}
    }).json()
    preview = client.post(f"/v1/changesets/{chg['id']}/preview-live", headers=AUTH)
    assert preview.status_code == 403
    assert preview.json()["detail"] == "Secret is denied by the beta.1 safety floor"
    stored = client.get(f"/v1/changesets/{chg['id']}").json()
    assert stored["state"] == "POLICY_DENIED"
    assert stored["preview"]["details"]["status_code"] == 403
    audit = client.get("/v1/audit").json()
    assert any(x["event_type"] == "changeset.policy_denied" and x["subject_id"] == chg["id"] for x in audit)


def test_live_preview_validation_failure_is_terminal(client: TestClient, monkeypatch):
    from fastapi import HTTPException

    target = setup_target(client)

    async def fake_post(path, payload):
        raise HTTPException(422, "invalid Helm chart reference")

    monkeypatch.setattr(cp.kubernetes_broker, "post", fake_post)
    chg = client.post("/v1/changesets", headers=AUTH, json={
        "operation": "helm.install", "adapter": "helm", "target_id": target["id"],
        "requested_by": "ui:requester", "parameters": {"release": "demo", "chart": "-bad", "namespace": "default"}
    }).json()
    preview = client.post(f"/v1/changesets/{chg['id']}/preview-live", headers=AUTH)
    assert preview.status_code == 422
    stored = client.get(f"/v1/changesets/{chg['id']}").json()
    assert stored["state"] == "PREVIEW_FAILED"
    assert stored["preview"]["details"]["detail"] == "invalid Helm chart reference"
