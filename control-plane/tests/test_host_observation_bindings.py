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
from hermes_control_plane.main import app  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin"}
CREDENTIAL = {"Authorization": "Bearer test-credential-service"}
FP = "SHA256:" + "D" * 43


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(app) as value:
        yield value


def _server(client: TestClient) -> dict:
    environment = client.post("/v1/environments", headers=ADMIN, json={"name": "Observer Test"}).json()
    credential = client.post(
        "/v1/internal/credential-refs/sync", headers=CREDENTIAL,
        json={"id": "cred_observer123", "name": "observer-ssh", "kind": "ssh-key", "provider": "credential-service", "status": "configured", "metadata": {"fingerprint": "sha256:ssh"}},
    ).json()
    response = client.post(
        "/v1/servers", headers=ADMIN,
        json={"hostname": "observer-node", "environment_id": environment["id"], "management_ip": "10.60.0.10", "host_fingerprint": FP, "connection_mode": "agent", "credential_ref": credential["id"]},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_host_observation_binding_is_server_local_and_closed(client: TestClient):
    server_id = _server(client)["id"]
    response = client.post(
        f"/v1/servers/{server_id}/host-observation-binding",
        headers=ADMIN,
        json={"collector_identity": "host-observer-a"},
    )
    assert response.status_code == 201
    binding = response.json()
    assert binding["server_id"] == server_id
    assert binding["collector_kind"] == "host-network-local-v1"
    assert binding["transport"] == "host-observer-default"

    assert client.post(
        f"/v1/servers/{server_id}/host-observation-binding",
        headers=ADMIN,
        json={"collector_identity": "host-observer-b", "url": "http://forbidden"},
    ).status_code == 422
    assert client.patch(
        f"/v1/servers/{server_id}/host-observation-binding",
        headers=ADMIN, json={"status": "disabled"},
    ).json()["status"] == "disabled"
