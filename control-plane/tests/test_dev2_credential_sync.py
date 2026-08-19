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
os.environ["HERMES_CREDENTIAL_SERVICE_TOKEN"] = "test-credential-service"

from hermes_control_plane import db  # noqa: E402
from hermes_control_plane.main import app  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin"}
CREDENTIAL_SERVICE = {"Authorization": "Bearer test-credential-service"}


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(app) as c:
        yield c


def test_credential_service_sync_identity_is_narrow_and_metadata_only(client: TestClient):
    payload = {
        "id": "cred_12345678abcdef",
        "name": "production-kubeconfig",
        "kind": "kubeconfig",
        "provider": "local-encrypted",
        "status": "configured",
        "metadata": {"backend": "local-encrypted", "fingerprint": "sha256:" + "a" * 64, "version": 1},
    }

    forbidden_admin = client.post("/v1/internal/credential-refs/sync", headers=ADMIN, json=payload)
    assert forbidden_admin.status_code == 403

    synced = client.post("/v1/internal/credential-refs/sync", headers=CREDENTIAL_SERVICE, json=payload)
    assert synced.status_code == 200, synced.text
    body = synced.json()
    assert body["id"] == payload["id"]
    assert body["metadata"]["fingerprint"] == payload["metadata"]["fingerprint"]

    raw = client.post(
        "/v1/internal/credential-refs/sync",
        headers=CREDENTIAL_SERVICE,
        json={**payload, "metadata": {"private_key": "forbidden"}},
    )
    assert raw.status_code == 422

    listed = client.get("/v1/credential-refs")
    assert len(listed.json()) == 1
    assert "private_key" not in listed.text


def test_credential_service_delete_fails_closed_when_reference_is_in_use(client: TestClient):
    payload = {
        "id": "cred_abcdef12345678",
        "name": "ssh-prod",
        "kind": "ssh-key",
        "provider": "vault",
        "metadata": {"backend": "vault", "external_ref": "kv/platform/ssh#key", "fingerprint": "ref:" + "b" * 64, "version": 1},
    }
    assert client.post("/v1/internal/credential-refs/sync", headers=CREDENTIAL_SERVICE, json=payload).status_code == 200

    env = client.post("/v1/environments", headers=ADMIN, json={"name": "Prod", "risk_level": "HIGH"}).json()
    target = client.post(
        "/v1/targets",
        headers=ADMIN,
        json={
            "name": "prod-ssh",
            "kind": "ssh",
            "environment_id": env["id"],
            "credential_ref": payload["id"],
            "connection_mode": "agent",
            "address": "ssh.example.internal",
            "scope": {"host_fingerprint": "SHA256:abc"},
        },
    )
    assert target.status_code == 201, target.text

    blocked = client.delete(f"/v1/internal/credential-refs/{payload['id']}", headers=CREDENTIAL_SERVICE)
    assert blocked.status_code == 409
    assert blocked.json()["detail"] == "credential reference is in use"
