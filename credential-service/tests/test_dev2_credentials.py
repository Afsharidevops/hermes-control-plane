from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

os.environ["HERMES_CREDENTIAL_ADMIN_TOKEN"] = "credential-admin-test"
os.environ["HERMES_CREDENTIAL_SERVICE_TOKEN"] = "credential-sync-test"
os.environ["HERMES_CONTROL_PLANE_URL"] = "http://control-plane.test"
os.environ["HERMES_CREDENTIAL_MASTER_KEY"] = Fernet.generate_key().decode("ascii")
os.environ["HERMES_CREDENTIAL_MASTER_KEY_VERSION"] = "test-v1"

from hermes_credential_service import store  # noqa: E402
from hermes_credential_service.main import app  # noqa: E402

AUTH = {"Authorization": "Bearer credential-admin-test"}


class FakeResponse:
    def __init__(self, status_code: int = 200, body: dict | None = None):
        self.status_code = status_code
        self._body = body or {}
        self.headers = {"content-type": "application/json"}

    def json(self):
        return self._body


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    store.DB_PATH = tmp_path / "credentials.sqlite3"
    synced: list[dict] = []

    def fake_post(url, *, headers, json, timeout):
        assert url.endswith("/v1/internal/credential-refs/sync")
        assert headers == {"Authorization": "Bearer credential-sync-test"}
        synced.append(json)
        return FakeResponse()

    def fake_delete(url, *, headers, timeout):
        assert "/v1/internal/credential-refs/" in url
        assert headers == {"Authorization": "Bearer credential-sync-test"}
        return FakeResponse(status_code=204)

    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.setattr(httpx, "delete", fake_delete)
    with TestClient(app) as c:
        c.synced = synced  # type: ignore[attr-defined]
        yield c


def _create_kubeconfig(client: TestClient, secret: str = "apiVersion: v1\nclusters: []\ncontexts: []\nusers: []\n") -> dict:
    response = client.post(
        "/v1/credentials",
        headers=AUTH,
        json={
            "name": "prod-kubeconfig",
            "kind": "kubeconfig",
            "backend": "local-encrypted",
            "secret_material": secret,
            "metadata": {"cluster_name": "production", "owner": "platform"},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_local_secret_is_encrypted_redacted_and_metadata_only_synced(client: TestClient):
    raw = "apiVersion: v1\nclusters: []\ncontexts: []\nusers: []\n"
    created = _create_kubeconfig(client, raw)
    assert created["material_state"] == "encrypted"
    assert "ciphertext" not in created
    assert "secret_material" not in json.dumps(created)
    assert created["fingerprint"].startswith("sha256:")

    with store.connect() as conn:
        row = conn.execute("SELECT ciphertext FROM credentials WHERE id=?", (created["id"],)).fetchone()
    assert row is not None
    assert raw.encode() not in bytes(row["ciphertext"])

    synced = client.synced[-1]  # type: ignore[attr-defined]
    serialized = json.dumps(synced, sort_keys=True)
    assert raw not in serialized
    assert "secret_material" not in serialized
    assert synced["id"] == created["id"]
    assert synced["metadata"]["fingerprint"] == created["fingerprint"]

    listed = client.get("/v1/credentials", headers=AUTH)
    assert listed.status_code == 200
    assert raw not in listed.text


def test_kubeconfig_test_and_rotation_never_return_plaintext(client: TestClient):
    created = _create_kubeconfig(client)
    tested = client.post(f"/v1/credentials/{created['id']}/test", headers=AUTH, json={"actor": "admin:test"})
    assert tested.status_code == 200, tested.text
    assert tested.json()["status"] == "VALID"
    assert tested.json()["detail"] == {"clusters": 0, "contexts": 0, "users": 0}

    replacement = "apiVersion: v1\nclusters:\n- name: prod\ncontexts: []\nusers: []\n"
    rotated = client.post(
        f"/v1/credentials/{created['id']}/rotate",
        headers=AUTH,
        json={"secret_material": replacement, "metadata": {"cluster_name": "production-v2"}},
    )
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["version"] == 2
    assert replacement not in rotated.text
    assert rotated.json()["fingerprint"] != created["fingerprint"]


def test_invalid_kubeconfig_returns_only_safe_reason(client: TestClient):
    created = _create_kubeconfig(client, "password: SUPERSECRET\n")
    tested = client.post(f"/v1/credentials/{created['id']}/test", headers=AUTH, json={})
    assert tested.status_code == 200
    assert tested.json()["status"] == "INVALID"
    assert "SUPERSECRET" not in tested.text


def test_external_backends_are_reference_only(client: TestClient):
    bad = client.post(
        "/v1/credentials",
        headers=AUTH,
        json={
            "name": "vault-bad",
            "kind": "token",
            "backend": "vault",
            "external_ref": "kv/data/platform/github#token",
            "secret_material": "must-not-be-accepted",
        },
    )
    assert bad.status_code == 422

    created = client.post(
        "/v1/credentials",
        headers=AUTH,
        json={
            "name": "vault-github",
            "kind": "token",
            "backend": "vault",
            "external_ref": "kv/data/platform/github#api-key",
            "metadata": {"mount": "kv", "scope": "platform"},
        },
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["material_state"] == "external-reference"
    assert body["fingerprint"].startswith("ref:")

    tested = client.post(f"/v1/credentials/{body['id']}/test", headers=AUTH, json={})
    assert tested.status_code == 200
    assert tested.json()["status"] == "REFERENCE_CONFIGURED"


def test_metadata_rejects_secret_shaped_fields(client: TestClient):
    response = client.post(
        "/v1/credentials",
        headers=AUTH,
        json={
            "name": "bad-metadata",
            "kind": "token",
            "backend": "local-encrypted",
            "secret_material": "actual-secret",
            "metadata": {"access_token": "leak"},
        },
    )
    assert response.status_code == 422
    assert "raw secret material is forbidden" in response.json()["detail"]


def test_delete_calls_control_plane_before_erasing_local_record(client: TestClient):
    created = _create_kubeconfig(client)
    deleted = client.delete(f"/v1/credentials/{created['id']}", headers=AUTH)
    assert deleted.status_code == 204
    missing = client.get(f"/v1/credentials/{created['id']}", headers=AUTH)
    assert missing.status_code == 404


def test_revoke_syncs_metadata_then_erases_local_ciphertext(client: TestClient):
    created = _create_kubeconfig(client)
    revoked = client.post(
        f"/v1/credentials/{created['id']}/revoke",
        headers=AUTH,
        json={"actor": "admin:security", "reason": "credential retired"},
    )
    assert revoked.status_code == 200, revoked.text
    body = revoked.json()
    assert body["status"] == "REVOKED"
    assert body["sync_status"] == "SYNCED"
    assert "ciphertext" not in body
    assert client.synced[-1]["status"] == "revoked"  # type: ignore[attr-defined]
    with store.connect() as conn:
        row = conn.execute("SELECT ciphertext FROM credentials WHERE id=?", (created["id"],)).fetchone()
    assert row["ciphertext"] is None
    tested = client.post(f"/v1/credentials/{created['id']}/test", headers=AUTH, json={})
    assert tested.status_code == 409


def test_create_and_rotate_fail_closed_when_control_plane_sync_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    store.DB_PATH = tmp_path / "credentials-fail.sqlite3"

    def reject_post(url, *, headers, json, timeout):
        return FakeResponse(status_code=503, body={"detail": "down"})

    monkeypatch.setattr(httpx, "post", reject_post)
    with TestClient(app) as c:
        failed = c.post(
            "/v1/credentials",
            headers=AUTH,
            json={
                "name": "must-not-persist",
                "kind": "token",
                "backend": "local-encrypted",
                "secret_material": "top-secret",
            },
        )
        assert failed.status_code == 502
    with store.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0] == 0


def test_ssh_private_key_lifecycle_and_audit_is_redacted(client: TestClient):
    key = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
    ).decode("utf-8")
    created = client.post(
        "/v1/credentials",
        headers=AUTH,
        json={
            "name": "prod-ssh-key",
            "kind": "ssh-key",
            "backend": "local-encrypted",
            "secret_material": key,
            "metadata": {"username": "platform", "host_group": "prod"},
        },
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert key not in created.text
    tested = client.post(f"/v1/credentials/{body['id']}/test", headers=AUTH, json={"actor": "admin:ssh-test"})
    assert tested.status_code == 200, tested.text
    assert tested.json()["status"] == "VALID"
    assert tested.json()["detail"] == {"format": "private-key"}

    audit = client.get("/v1/audit", headers=AUTH)
    assert audit.status_code == 200
    serialized = audit.text
    assert key not in serialized
    event_types = {event["event_type"] for event in audit.json()}
    assert {"credential.created", "credential.tested"} <= event_types


def test_rotation_fails_closed_and_preserves_previous_ciphertext(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    created = _create_kubeconfig(client)
    with store.connect() as conn:
        before = conn.execute("SELECT version,ciphertext,fingerprint FROM credentials WHERE id=?", (created["id"],)).fetchone()
        before_tuple = (int(before["version"]), bytes(before["ciphertext"]), before["fingerprint"])

    def reject_post(url, *, headers, json, timeout):
        return FakeResponse(status_code=503, body={"detail": "down"})

    monkeypatch.setattr(httpx, "post", reject_post)
    failed = client.post(
        f"/v1/credentials/{created['id']}/rotate",
        headers=AUTH,
        json={"secret_material": "apiVersion: v1\nclusters: []\ncontexts: []\nusers: []\n# changed\n"},
    )
    assert failed.status_code == 502
    with store.connect() as conn:
        after = conn.execute("SELECT version,ciphertext,fingerprint FROM credentials WHERE id=?", (created["id"],)).fetchone()
        after_tuple = (int(after["version"]), bytes(after["ciphertext"]), after["fingerprint"])
    assert after_tuple == before_tuple


def test_metadata_update_is_redacted_synced_and_audited(client: TestClient):
    created = _create_kubeconfig(client)
    updated = client.patch(
        f"/v1/credentials/{created['id']}",
        headers=AUTH,
        json={
            "name": "prod-kubeconfig-renamed",
            "metadata": {"cluster_name": "production", "owner": "sre", "bastion_ref": "srv_jump01"},
            "actor": "admin:metadata-update",
        },
    )
    assert updated.status_code == 200, updated.text
    body = updated.json()
    assert body["name"] == "prod-kubeconfig-renamed"
    assert body["metadata"]["owner"] == "sre"
    assert body["metadata"]["bastion_ref"] == "srv_jump01"
    assert body["version"] == 1  # secret-material versions change only through rotate
    assert "ciphertext" not in body and "secret_material" not in updated.text
    synced = client.synced[-1]  # type: ignore[attr-defined]
    assert synced["name"] == "prod-kubeconfig-renamed"
    assert synced["metadata"]["owner"] == "sre"

    audit = client.get("/v1/audit", headers=AUTH)
    event = next(item for item in audit.json() if item["event_type"] == "credential.updated")
    assert event["actor"] == "admin:metadata-update"
    assert event["payload"] == {"fields": ["name", "metadata"]}


def test_metadata_update_fails_closed_when_control_plane_sync_fails(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    created = _create_kubeconfig(client)
    with store.connect() as conn:
        before = conn.execute("SELECT name,metadata_json,updated_at FROM credentials WHERE id=?", (created["id"],)).fetchone()
        before_tuple = (before["name"], before["metadata_json"], int(before["updated_at"]))

    def reject_post(url, *, headers, json, timeout):
        return FakeResponse(status_code=503, body={"detail": "down"})

    monkeypatch.setattr(httpx, "post", reject_post)
    failed = client.patch(
        f"/v1/credentials/{created['id']}",
        headers=AUTH,
        json={"name": "should-rollback", "metadata": {"owner": "rollback-test"}},
    )
    assert failed.status_code == 502
    with store.connect() as conn:
        after = conn.execute("SELECT name,metadata_json,updated_at FROM credentials WHERE id=?", (created["id"],)).fetchone()
        after_tuple = (after["name"], after["metadata_json"], int(after["updated_at"]))
    assert after_tuple == before_tuple
