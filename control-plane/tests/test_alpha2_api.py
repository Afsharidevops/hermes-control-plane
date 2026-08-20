from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ["HERMES_CONTROL_ADMIN_TOKEN"] = "test-admin"
os.environ["HERMES_BOT_SERVICE_TOKEN"] = "test-bot"
os.environ["HERMES_APPROVAL_BOT_TOKEN"] = "test-approval"
os.environ["HERMES_APPROVAL_HMAC_KEY"] = "approval-hmac-key-0123456789abcdef0123456789abcdef"

from hermes_control_plane import db  # noqa: E402
from hermes_control_plane.main import app  # noqa: E402

AUTH = {"Authorization": "Bearer test-admin"}
BOT_AUTH = {"Authorization": "Bearer test-bot"}
APPROVAL_AUTH = {"Authorization": "Bearer test-approval"}


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(app) as c:
        yield c


def create_env(client: TestClient, name: str = "Production", risk: str = "HIGH") -> dict:
    r = client.post("/v1/environments", headers=AUTH, json={"name": name, "risk_level": risk})
    assert r.status_code == 201, r.text
    return r.json()


def test_registry_crud_and_credential_refs_are_metadata_only(client: TestClient):
    env = create_env(client)
    cred = client.post("/v1/credential-refs", headers=AUTH, json={"name": "prod-kube", "kind": "kubeconfig", "metadata": {"owner": "platform"}})
    assert cred.status_code == 201
    credj = cred.json()
    assert credj["secret_material_stored"] is False

    integration = client.post(
        "/v1/integrations",
        headers=AUTH,
        json={
            "name": "prod-k8s-api",
            "kind": "kubernetes",
            "environment_id": env["id"],
            "endpoint": "https://kubernetes.example.invalid",
            "credential_ref": credj["id"],
            "connection_mode": "direct",
            "allowed_scope": {"namespaces": ["apps"]},
        },
    )
    assert integration.status_code == 201, integration.text
    integ = integration.json()

    target = client.post(
        "/v1/targets",
        headers=AUTH,
        json={
            "name": "production-k8s",
            "kind": "kubernetes",
            "environment_id": env["id"],
            "integration_id": integ["id"],
            "credential_ref": credj["id"],
            "connection_mode": "direct",
            "scope": {"namespace_allowlist": ["apps"]},
        },
    )
    assert target.status_code == 201, target.text
    assert target.json()["scope"]["namespace_allowlist"] == ["apps"]

    assert client.get("/v1/environments").status_code == 200
    assert client.get("/v1/integrations").status_code == 200
    assert client.get("/v1/targets").status_code == 200
    assert client.get("/v1/credential-refs").status_code == 200


def test_changeset_hash_risk_preview_and_approval_binding(client: TestClient):
    env = create_env(client)
    target = client.post(
        "/v1/targets",
        headers=AUTH,
        json={"name": "prod", "kind": "kubernetes", "environment_id": env["id"], "connection_mode": "direct"},
    ).json()

    payload = {
        "operation": "kubernetes.deployment.scale",
        "adapter": "kubernetes",
        "target_id": target["id"],
        "requested_by": "telegram:1001",
        "source_channel": "telegram",
        "source_revision": "git:deadbeef",
        "parameters": {"namespace": "apps", "deployment": "api", "replicas": 5},
    }
    r = client.post("/v1/changesets", headers=BOT_AUTH, json=payload)
    assert r.status_code == 201, r.text
    chg = r.json()
    assert chg["risk"] == "HIGH"
    assert chg["approval_required"] is True
    assert len(chg["plan_hash"]) == 64
    assert chg["executable"] is False

    preview = client.post(f"/v1/changesets/{chg['id']}/preview", headers=BOT_AUTH, json={"summary": "Scale api 3 -> 5", "details": {"creates": 0, "updates": 1, "deletes": 0}})
    assert preview.status_code == 200
    assert preview.json()["state"] == "PREVIEWED"

    req = client.post(f"/v1/changesets/{chg['id']}/request-approval", headers=BOT_AUTH)
    assert req.status_code == 200
    assert req.json()["state"] == "AWAITING_APPROVAL"

    bad_hash = client.post(f"/v1/changesets/{chg['id']}/approve", headers=APPROVAL_AUTH, json={"approver": "telegram:2002", "plan_hash": "0" * 64})
    assert bad_hash.status_code == 409

    self_approval = client.post(f"/v1/changesets/{chg['id']}/approve", headers=APPROVAL_AUTH, json={"approver": "telegram:1001", "plan_hash": chg["plan_hash"]})
    assert self_approval.status_code == 403

    ok = client.post(f"/v1/changesets/{chg['id']}/approve", headers=APPROVAL_AUTH, json={"approver": "telegram:2002", "plan_hash": chg["plan_hash"]})
    assert ok.status_code == 201, ok.text
    assert ok.json()["execution_enabled"] is False

    final = client.get(f"/v1/changesets/{chg['id']}").json()
    assert final["state"] == "APPROVED"


def test_read_operation_does_not_require_approval(client: TestClient):
    env = create_env(client, "Dev", "LOW")
    target = client.post("/v1/targets", headers=AUTH, json={"name": "dev", "kind": "kubernetes", "environment_id": env["id"], "connection_mode": "direct"}).json()
    chg = client.post("/v1/changesets", headers=AUTH, json={"operation": "list.pods", "adapter": "kubernetes", "target_id": target["id"], "requested_by": "ui:me", "parameters": {}}).json()
    assert chg["risk"] == "READ"
    assert chg["approval_required"] is False


def test_audit_events_are_written(client: TestClient):
    env = create_env(client)
    rows = client.get("/v1/audit").json()
    assert any(row["event_type"] == "environment.created" and row["subject_id"] == env["id"] for row in rows)


def test_ui_is_served(client: TestClient):
    r = client.get("/ui")
    assert r.status_code == 200
    assert "0.5.11-dev.5 · Scope Closure + runtime integration" in r.text
