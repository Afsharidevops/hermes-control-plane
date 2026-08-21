from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ["HERMES_CONTROL_ADMIN_TOKEN"] = "test-admin"
os.environ["HERMES_BOT_SERVICE_TOKEN"] = "test-bot"
os.environ["HERMES_APPROVAL_BOT_TOKEN"] = "test-approval"
os.environ["HERMES_APPROVAL_HMAC_KEY"] = "approval-hmac-key-0123456789abcdef0123456789abcdef"
os.environ["HERMES_EXECUTION_HMAC_KEY"] = "execution-ticket-key-0123456789abcdef0123456789abcdef"

from hermes_control_plane import db  # noqa: E402
from hermes_control_plane.main import app  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin"}
BOT = {"Authorization": "Bearer test-bot"}
APPROVAL = {"Authorization": "Bearer test-approval"}
NAMESPACE = "community"
NAME = "general"
VERSION = "10.4.0"


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(app) as c:
        yield c


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest(data: bytes) -> str:
    return "sha256:" + _sha256(data)


def _collection_archive(*, namespace: str = NAMESPACE, name: str = NAME, version: str = VERSION, files_checksum_override: str | None = None, symlink: bool = False) -> bytes:
    readme = b"# offline collection\n"
    files_doc = {
        "format": 1,
        "files": [
            {"name": "README.md", "ftype": "file", "chksum_type": "sha256", "chksum_sha256": _sha256(readme)},
        ],
    }
    files_raw = json.dumps(files_doc, sort_keys=True, separators=(",", ":")).encode()
    manifest_doc = {
        "collection_info": {
            "namespace": namespace,
            "name": name,
            "version": version,
            "authors": ["Hermes test"],
            "readme": "README.md",
            "tags": [],
            "description": "offline collection fixture",
            "license": [],
            "license_file": None,
            "dependencies": {},
            "repository": None,
            "documentation": None,
            "homepage": None,
            "issues": None,
        },
        "file_manifest_file": {
            "name": "FILES.json",
            "ftype": "file",
            "chksum_type": "sha256",
            "chksum_sha256": files_checksum_override or _sha256(files_raw),
        },
        "format": 1,
    }
    manifest_raw = json.dumps(manifest_doc, sort_keys=True, separators=(",", ":")).encode()

    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for filename, data in (("MANIFEST.json", manifest_raw), ("FILES.json", files_raw), ("README.md", readme)):
            info = tarfile.TarInfo(filename)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
        if symlink:
            link = tarfile.TarInfo("roles/escape")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../etc/passwd"
            link.mtime = 0
            archive.addfile(link)
    return output.getvalue()


def _plan(client: TestClient, tmp_path: Path, archive: bytes, *, labels: dict[str, str] | None = None, version: str = VERSION) -> tuple[dict, Path]:
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    source_root.mkdir(exist_ok=True)
    mirror_root.mkdir(exist_ok=True)
    source = source_root / f"{NAMESPACE}-{NAME}-{version}.tar.gz"
    source.write_bytes(archive)
    destination = mirror_root / "ansible" / source.name
    created = client.post(
        "/v1/artifact-mirror/items",
        headers=ADMIN,
        json={
            "name": f"{NAMESPACE}.{NAME}-{version}",
            "kind": "ansible-collection",
            "source": source.as_uri(),
            "destination": destination.as_uri(),
            "version": version,
            "digest": _digest(archive),
            "labels": labels or {"ansible_namespace": NAMESPACE, "ansible_name": NAME, "component": "provider:kubespray"},
        },
    )
    assert created.status_code == 201, created.text
    planned = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={
            "requested_by": "hermes-bot:ansible-offline",
            "source_channel": "hermes-bot",
            "domain": "artifact",
            "operation": "artifact.mirror.apply",
            "target_id": created.json()["id"],
            "parameters": {"verify_destination": True},
        },
    )
    assert planned.status_code == 201, planned.text
    body = planned.json()
    assert body["operation_plan"]["plan"]["runtime"]["mode"] == "ansible-collection-archive"
    assert body["operation_job"]["executor"] == "artifact-mirror-worker"
    expected_labels = labels or {"ansible_namespace": NAMESPACE, "ansible_name": NAME, "component": "provider:kubespray"}
    assert body["operation_plan"]["plan"]["artifact"]["labels"] == {
        key: expected_labels[key] for key in ("ansible_namespace", "ansible_name") if key in expected_labels
    }
    return body, destination


def _authorize(client: TestClient, body: dict) -> dict:
    changeset = body["changeset"]
    requested = client.post(f"/v1/changesets/{changeset['id']}/request-approval", headers=BOT)
    assert requested.status_code == 200, requested.text
    approved = client.post(
        f"/v1/changesets/{changeset['id']}/approve",
        headers=APPROVAL,
        json={"approver": "approval-bot:ansible", "plan_hash": changeset["plan_hash"]},
    )
    assert approved.status_code == 201, approved.text
    authorized = client.post(f"/v1/operation-jobs/{body['operation_job']['id']}/authorize", headers=BOT)
    assert authorized.status_code == 200, authorized.text
    return authorized.json()


def _execute(client: TestClient, body: dict, auth: dict) -> dict:
    response = client.post(
        f"/v1/operation-jobs/{body['operation_job']['id']}/execute",
        headers=BOT,
        json={"execution_ticket": auth["execution_ticket"], "signature": auth["signature"], "actor": "hermes-bot:ansible"},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_ansible_collection_archive_identity_checksums_and_idempotency(client: TestClient, tmp_path: Path, monkeypatch):
    archive = _collection_archive()
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    monkeypatch.setenv("HERMES_ARTIFACT_SOURCE_ROOT", str(source_root))
    monkeypatch.setenv("HERMES_ARTIFACT_MIRROR_ROOT", str(mirror_root))

    body, destination = _plan(client, tmp_path, archive)
    result = _execute(client, body, _authorize(client, body))
    assert result["operation_job"]["state"] == "SUCCEEDED"
    assert result["runtime_result"]["state"] == "MIRRORED"
    evidence = result["runtime_result"]["verification"]["evidence"]
    assert evidence["ansible_namespace"] == NAMESPACE
    assert evidence["ansible_name"] == NAME
    assert evidence["ansible_version"] == VERSION
    assert evidence["verified_regular_files"] == 1
    assert evidence["archive_extracted_to_filesystem"] is False
    assert result["verification"]["status"] == "PASS"
    assert destination.read_bytes() == archive

    second = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={
            "requested_by": "hermes-bot:ansible-retry",
            "source_channel": "hermes-bot",
            "domain": "artifact",
            "operation": "artifact.mirror.apply",
            "target_id": body["operation_plan"]["subject_id"],
            "parameters": {"verify_destination": True},
        },
    ).json()
    source_path = source_root / f"{NAMESPACE}-{NAME}-{VERSION}.tar.gz"
    source_path.unlink()
    retried = _execute(client, second, _authorize(client, second))
    assert retried["runtime_result"]["state"] == "ALREADY_MIRRORED"
    assert retried["runtime_result"]["verification"]["evidence"]["idempotent"] is True


def test_ansible_collection_rejects_manifest_identity_mismatch(client: TestClient, tmp_path: Path, monkeypatch):
    archive = _collection_archive(namespace="other")
    monkeypatch.setenv("HERMES_ARTIFACT_SOURCE_ROOT", str(tmp_path / "source"))
    monkeypatch.setenv("HERMES_ARTIFACT_MIRROR_ROOT", str(tmp_path / "mirror"))
    body, _ = _plan(client, tmp_path, archive)
    result = _execute(client, body, _authorize(client, body))
    assert result["runtime_result"]["state"] == "FAILED"
    assert "identity/version" in result["runtime_result"]["verification"]["checks"][0]["summary"]


def test_ansible_collection_rejects_files_manifest_checksum_drift(client: TestClient, tmp_path: Path, monkeypatch):
    archive = _collection_archive(files_checksum_override="0" * 64)
    monkeypatch.setenv("HERMES_ARTIFACT_SOURCE_ROOT", str(tmp_path / "source"))
    monkeypatch.setenv("HERMES_ARTIFACT_MIRROR_ROOT", str(tmp_path / "mirror"))
    body, _ = _plan(client, tmp_path, archive)
    result = _execute(client, body, _authorize(client, body))
    assert result["runtime_result"]["state"] == "FAILED"
    assert "FILES.json checksum" in result["runtime_result"]["verification"]["checks"][0]["summary"]


def test_ansible_collection_rejects_symlink_archive_member(client: TestClient, tmp_path: Path, monkeypatch):
    archive = _collection_archive(symlink=True)
    monkeypatch.setenv("HERMES_ARTIFACT_SOURCE_ROOT", str(tmp_path / "source"))
    monkeypatch.setenv("HERMES_ARTIFACT_MIRROR_ROOT", str(tmp_path / "mirror"))
    body, _ = _plan(client, tmp_path, archive)
    result = _execute(client, body, _authorize(client, body))
    assert result["runtime_result"]["state"] == "FAILED"
    assert "link/device" in result["runtime_result"]["verification"]["checks"][0]["summary"]


def test_ansible_collection_filters_nonruntime_labels_and_rejects_invalid_identity_version(client: TestClient, tmp_path: Path, monkeypatch):
    archive = _collection_archive()
    monkeypatch.setenv("HERMES_ARTIFACT_SOURCE_ROOT", str(tmp_path / "source"))
    monkeypatch.setenv("HERMES_ARTIFACT_MIRROR_ROOT", str(tmp_path / "mirror"))

    # Classification/dependency labels may exist on the stored artifact, but only the
    # two collection-identity labels enter the execution plan.
    body, _ = _plan(client, tmp_path, archive, labels={"ansible_namespace": NAMESPACE, "ansible_name": NAME, "component": "provider:kubespray"})
    result = _execute(client, body, _authorize(client, body))
    assert result["runtime_result"]["state"] == "MIRRORED"

    invalid_identity = _collection_archive(namespace="Bad-Namespace", version="10.4.1")
    body2, _ = _plan(client, tmp_path, invalid_identity, labels={"ansible_namespace": "Bad-Namespace", "ansible_name": NAME}, version="10.4.1")
    result2 = _execute(client, body2, _authorize(client, body2))
    assert result2["runtime_result"]["state"] == "FAILED"
    assert "namespace is invalid" in result2["runtime_result"]["verification"]["checks"][0]["summary"]

    bad_version_archive = _collection_archive(version="not-semver")
    body3, _ = _plan(client, tmp_path, bad_version_archive, version="not-semver")
    result3 = _execute(client, body3, _authorize(client, body3))
    assert result3["runtime_result"]["state"] == "FAILED"
    assert "semantic-version" in result3["runtime_result"]["verification"]["checks"][0]["summary"]
