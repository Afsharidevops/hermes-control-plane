from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ["HERMES_CONTROL_ADMIN_TOKEN"] = "test-admin"
os.environ["HERMES_BOT_SERVICE_TOKEN"] = "test-bot"
os.environ["HERMES_APPROVAL_BOT_TOKEN"] = "test-approval"
os.environ["HERMES_APPROVAL_HMAC_KEY"] = "approval-hmac-key-0123456789abcdef0123456789abcdef"
os.environ["HERMES_EXECUTION_HMAC_KEY"] = "execution-ticket-key-0123456789abcdef0123456789abcdef"

from hermes_control_plane import artifact_mirror, db  # noqa: E402
from hermes_control_plane.main import app  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin"}
BOT = {"Authorization": "Bearer test-bot"}
APPROVAL = {"Authorization": "Bearer test-approval"}


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(app) as c:
        yield c


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _approve_and_authorize(client: TestClient, body: dict) -> dict:
    changeset = body["changeset"]
    requested = client.post(f"/v1/changesets/{changeset['id']}/request-approval", headers=BOT)
    assert requested.status_code == 200, requested.text
    approved = client.post(
        f"/v1/changesets/{changeset['id']}/approve",
        headers=APPROVAL,
        json={"approver": "approval-bot:artifact", "plan_hash": changeset["plan_hash"]},
    )
    assert approved.status_code == 201, approved.text
    authorized = client.post(f"/v1/operation-jobs/{body['operation_job']['id']}/authorize", headers=BOT)
    assert authorized.status_code == 200, authorized.text
    return authorized.json()


def _plan_file_mirror(client: TestClient, source: Path, destination: Path, digest: str, *, replace_existing: bool = False) -> dict:
    created = client.post(
        "/v1/artifact-mirror/items",
        headers=ADMIN,
        json={
            "name": f"artifact-{source.stem}-{destination.stem}",
            "kind": "git-release",
            "source": source.as_uri(),
            "destination": destination.as_uri(),
            "version": "v1.2.3",
            "digest": digest,
        },
    )
    assert created.status_code == 201, created.text
    planned = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={
            "requested_by": "hermes-bot:airgap",
            "source_channel": "hermes-bot",
            "domain": "artifact",
            "operation": "artifact.mirror.apply",
            "target_id": created.json()["id"],
            "parameters": {"verify_destination": True, "replace_existing": replace_existing},
        },
    )
    assert planned.status_code == 201, planned.text
    return planned.json()


def test_file_artifact_mirror_executes_digest_verified_and_is_idempotent(client: TestClient, tmp_path: Path, monkeypatch):
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    source_root.mkdir()
    mirror_root.mkdir()
    monkeypatch.setenv("HERMES_ARTIFACT_SOURCE_ROOT", str(source_root))
    monkeypatch.setenv("HERMES_ARTIFACT_MIRROR_ROOT", str(mirror_root))
    data = b"hermes-airgap-artifact-v1\n"
    source = source_root / "release.tgz"
    destination = mirror_root / "git" / "release.tgz"
    source.write_bytes(data)

    body = _plan_file_mirror(client, source, destination, _digest(data))
    assert body["operation_job"]["executor"] == "artifact-mirror-worker"
    assert body["operation_plan"]["plan"]["runtime"]["state"] == "RUNTIME_CAPABLE"
    auth = _approve_and_authorize(client, body)
    executed = client.post(
        f"/v1/operation-jobs/{body['operation_job']['id']}/execute",
        headers=BOT,
        json={"execution_ticket": auth["execution_ticket"], "signature": auth["signature"], "actor": "hermes-bot:airgap"},
    )
    assert executed.status_code == 200, executed.text
    result = executed.json()
    assert result["operation_job"]["state"] == "SUCCEEDED"
    assert result["verification"]["status"] == "PASS"
    assert result["runtime_result"]["state"] == "MIRRORED"
    assert destination.read_bytes() == data
    assert {item["id"]: item["status"] for item in result["verification"]["checks"]} == {"source-digest": "PASS", "destination-digest": "PASS"}

    item_id = body["operation_plan"]["subject_id"]
    item = {row["id"]: row for row in client.get("/v1/artifact-mirror/items", headers=ADMIN).json()}[item_id]
    assert item["status"] == "configured"
    assert item["verification"]["status"] == "PASS"
    assert item["verification"]["sync_state"] == "MIRRORED"

    # A second exact plan is retry-safe and does not rewrite the valid destination.
    second = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={
            "requested_by": "hermes-bot:airgap-retry",
            "source_channel": "hermes-bot",
            "domain": "artifact",
            "operation": "artifact.mirror.apply",
            "target_id": item_id,
            "parameters": {"verify_destination": True},
        },
    )
    assert second.status_code == 201, second.text
    second_body = second.json()
    second_auth = _approve_and_authorize(client, second_body)
    retried = client.post(
        f"/v1/operation-jobs/{second_body['operation_job']['id']}/execute",
        headers=BOT,
        json={"execution_ticket": second_auth["execution_ticket"], "signature": second_auth["signature"], "actor": "hermes-bot:airgap-retry"},
    )
    assert retried.status_code == 200, retried.text
    assert retried.json()["runtime_result"]["state"] == "ALREADY_MIRRORED"
    assert retried.json()["verification"]["status"] == "PASS"


def test_artifact_mirror_digest_mismatch_fails_without_publishing_destination(client: TestClient, tmp_path: Path, monkeypatch):
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    source_root.mkdir()
    mirror_root.mkdir()
    monkeypatch.setenv("HERMES_ARTIFACT_SOURCE_ROOT", str(source_root))
    monkeypatch.setenv("HERMES_ARTIFACT_MIRROR_ROOT", str(mirror_root))
    source = source_root / "tampered.bin"
    destination = mirror_root / "tampered.bin"
    source.write_bytes(b"tampered")

    body = _plan_file_mirror(client, source, destination, "sha256:" + "a" * 64)
    auth = _approve_and_authorize(client, body)
    executed = client.post(
        f"/v1/operation-jobs/{body['operation_job']['id']}/execute",
        headers=BOT,
        json={"execution_ticket": auth["execution_ticket"], "signature": auth["signature"], "actor": "hermes-bot:airgap"},
    )
    assert executed.status_code == 200, executed.text
    result = executed.json()
    assert result["operation_job"]["state"] == "FAILED"
    assert result["verification"]["status"] == "FAIL"
    assert result["verification"]["checks"][0]["id"] == "source-digest"
    assert not destination.exists()
    changeset = client.get(f"/v1/changesets/{body['changeset']['id']}").json()
    assert changeset["state"] == "FAILED"


def test_artifact_protocol_contract_stays_non_executable_and_parameters_are_strict(client: TestClient):
    digest = "sha256:" + "b" * 64
    item = client.post(
        "/v1/artifact-mirror/items",
        headers=ADMIN,
        json={"name": "repo-package", "kind": "package", "source": "apt://repo.example/stable", "destination": "apt://mirror.local/stable", "version": "1.2.3", "digest": digest},
    )
    assert item.status_code == 201, item.text
    planned = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={"requested_by": "hermes-bot:airgap", "source_channel": "hermes-bot", "domain": "artifact", "operation": "artifact.mirror.apply", "target_id": item.json()["id"], "parameters": {"verify_destination": True}},
    )
    assert planned.status_code == 201, planned.text
    assert planned.json()["operation_job"]["executor"] == "artifact-mirror-contract"
    assert planned.json()["operation_plan"]["plan"]["runtime"]["state"] == "CONTRACT_ONLY"

    bad = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={"requested_by": "hermes-bot:airgap", "source_channel": "hermes-bot", "domain": "artifact", "operation": "artifact.mirror.apply", "target_id": item.json()["id"], "parameters": {"verify_destination": False}},
    )
    assert bad.status_code == 422
    assert "verification cannot be disabled" in bad.text



def test_oci_registry_mirror_is_digest_pinned_multiarch_and_idempotent(client: TestClient, monkeypatch, tmp_path: Path):
    manifest = b'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}'
    digest = _digest(manifest)
    monkeypatch.setenv("HERMES_ARTIFACT_OCI_SOURCE_REGISTRY_ALLOWLIST", "registry.example")
    monkeypatch.setenv("HERMES_ARTIFACT_OCI_DESTINATION_REGISTRY_ALLOWLIST", "mirror.local")
    monkeypatch.setenv("HERMES_ARTIFACT_AUTH_ROOT", str(tmp_path / "auth"))

    state = {"copied": False}
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(list(command))
        assert command[0] == "skopeo"
        assert kwargs.get("stdin") is subprocess.DEVNULL
        assert kwargs.get("stdout") is subprocess.PIPE
        assert kwargs.get("stderr") is subprocess.PIPE
        if command[1] == "inspect":
            ref = command[-1]
            if ref.startswith("docker://registry.example/"):
                return subprocess.CompletedProcess(command, 0, stdout=manifest, stderr=b"")
            if ref == "docker://mirror.local/hermes/cilium:1.19.4" and not state["copied"]:
                return subprocess.CompletedProcess(command, 1, stdout=b"", stderr=b"manifest unknown")
            if ref.startswith("docker://mirror.local/"):
                return subprocess.CompletedProcess(command, 0, stdout=manifest, stderr=b"")
        if command[1] == "copy":
            assert "--all" in command
            assert "--preserve-digests" in command
            assert "--retry-times" in command
            assert command[-2] == f"docker://registry.example/cilium/cilium@{digest}"
            assert command[-1] == "docker://mirror.local/hermes/cilium:1.19.4"
            digest_path = Path(command[command.index("--digestfile") + 1])
            digest_path.write_text(digest + "\n", encoding="utf-8")
            state["copied"] = True
            return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")
        raise AssertionError(command)

    monkeypatch.setattr(artifact_mirror.subprocess, "run", fake_run)

    created = client.post(
        "/v1/artifact-mirror/items",
        headers=ADMIN,
        json={
            "name": "oci-cilium-runtime",
            "kind": "oci-image",
            "source": "oci://registry.example/cilium/cilium",
            "destination": "oci://mirror.local/hermes/cilium",
            "version": "1.19.4",
            "digest": digest,
        },
    )
    assert created.status_code == 201, created.text
    planned = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={
            "requested_by": "hermes-bot:airgap",
            "source_channel": "hermes-bot",
            "domain": "artifact",
            "operation": "artifact.mirror.apply",
            "target_id": created.json()["id"],
            "parameters": {"verify_destination": True},
        },
    )
    assert planned.status_code == 201, planned.text
    body = planned.json()
    assert body["operation_job"]["executor"] == "artifact-mirror-worker"
    assert body["operation_plan"]["plan"]["runtime"]["state"] == "RUNTIME_CAPABLE"
    auth = _approve_and_authorize(client, body)
    executed = client.post(
        f"/v1/operation-jobs/{body['operation_job']['id']}/execute",
        headers=BOT,
        json={"execution_ticket": auth["execution_ticket"], "signature": auth["signature"], "actor": "hermes-bot:airgap"},
    )
    assert executed.status_code == 200, executed.text
    result = executed.json()
    assert result["operation_job"]["state"] == "SUCCEEDED"
    assert result["runtime_result"]["state"] == "MIRRORED"
    assert result["runtime_result"]["digest"] == digest
    assert result["runtime_result"]["verification"]["evidence"]["multi_arch"] == "all"
    assert result["runtime_result"]["verification"]["evidence"]["raw_credentials_returned"] is False

    # Exact retry observes the already-published tag and does not invoke copy again.
    second = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={
            "requested_by": "hermes-bot:airgap-retry",
            "source_channel": "hermes-bot",
            "domain": "artifact",
            "operation": "artifact.mirror.apply",
            "target_id": created.json()["id"],
            "parameters": {"verify_destination": True},
        },
    ).json()
    second_auth = _approve_and_authorize(client, second)
    retried = client.post(
        f"/v1/operation-jobs/{second['operation_job']['id']}/execute",
        headers=BOT,
        json={"execution_ticket": second_auth["execution_ticket"], "signature": second_auth["signature"], "actor": "hermes-bot:airgap-retry"},
    )
    assert retried.status_code == 200, retried.text
    assert retried.json()["runtime_result"]["state"] == "ALREADY_MIRRORED"
    assert sum(1 for call in calls if len(call) > 1 and call[1] == "copy") == 1


def test_oci_registry_mirror_rejects_unallowlisted_registry_and_embedded_reference_tags(client: TestClient, monkeypatch):
    manifest = b'{"schemaVersion":2}'
    digest = _digest(manifest)
    monkeypatch.setenv("HERMES_ARTIFACT_OCI_SOURCE_REGISTRY_ALLOWLIST", "registry.example")
    monkeypatch.setenv("HERMES_ARTIFACT_OCI_DESTINATION_REGISTRY_ALLOWLIST", "mirror.local")

    created = client.post(
        "/v1/artifact-mirror/items",
        headers=ADMIN,
        json={
            "name": "oci-untrusted",
            "kind": "oci-image",
            "source": "oci://evil.example/cilium/cilium",
            "destination": "oci://mirror.local/hermes/cilium",
            "version": "1.19.4",
            "digest": digest,
        },
    )
    assert created.status_code == 201
    planned = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={"requested_by": "hermes-bot:airgap", "source_channel": "hermes-bot", "domain": "artifact", "operation": "artifact.mirror.apply", "target_id": created.json()["id"], "parameters": {"verify_destination": True}},
    ).json()
    auth = _approve_and_authorize(client, planned)
    executed = client.post(
        f"/v1/operation-jobs/{planned['operation_job']['id']}/execute",
        headers=BOT,
        json={"execution_ticket": auth["execution_ticket"], "signature": auth["signature"], "actor": "hermes-bot:airgap"},
    )
    assert executed.status_code == 200
    assert executed.json()["runtime_result"]["state"] == "FAILED"
    assert "allowlisted" in executed.json()["runtime_result"]["verification"]["checks"][0]["summary"]


def test_helm_oci_registry_mirror_requires_helm_media_types_and_is_idempotent(client: TestClient, monkeypatch):
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.cncf.helm.config.v1+json",
                "digest": "sha256:" + "1" * 64,
                "size": 128,
            },
            "layers": [
                {
                    "mediaType": "application/vnd.cncf.helm.chart.content.v1.tar+gzip",
                    "digest": "sha256:" + "2" * 64,
                    "size": 512,
                }
            ],
        },
        separators=(",", ":"),
    ).encode()
    digest = _digest(manifest)
    monkeypatch.setenv("HERMES_ARTIFACT_OCI_SOURCE_REGISTRY_ALLOWLIST", "registry.example")
    monkeypatch.setenv("HERMES_ARTIFACT_OCI_DESTINATION_REGISTRY_ALLOWLIST", "mirror.local")

    state = {"copied": False}
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(list(command))
        if command[1] == "inspect":
            ref = command[-1]
            if ref.startswith("docker://registry.example/"):
                return subprocess.CompletedProcess(command, 0, stdout=manifest, stderr=b"")
            if ref == "docker://mirror.local/charts/cilium:1.18.1" and not state["copied"]:
                return subprocess.CompletedProcess(command, 1, stdout=b"", stderr=b"manifest unknown")
            if ref.startswith("docker://mirror.local/"):
                return subprocess.CompletedProcess(command, 0, stdout=manifest, stderr=b"")
        if command[1] == "copy":
            assert "--preserve-digests" in command
            assert command[-2] == f"docker://registry.example/charts/cilium@{digest}"
            assert command[-1] == "docker://mirror.local/charts/cilium:1.18.1"
            Path(command[command.index("--digestfile") + 1]).write_text(digest + "\n", encoding="utf-8")
            state["copied"] = True
            return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")
        raise AssertionError(command)

    monkeypatch.setattr(artifact_mirror.subprocess, "run", fake_run)
    created = client.post(
        "/v1/artifact-mirror/items",
        headers=ADMIN,
        json={
            "name": "helm-cilium-runtime",
            "kind": "helm-chart",
            "source": "oci://registry.example/charts/cilium",
            "destination": "oci://mirror.local/charts/cilium",
            "version": "1.18.1",
            "digest": digest,
        },
    )
    assert created.status_code == 201, created.text
    planned = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={"requested_by": "hermes-bot:airgap", "source_channel": "hermes-bot", "domain": "artifact", "operation": "artifact.mirror.apply", "target_id": created.json()["id"], "parameters": {"verify_destination": True}},
    )
    assert planned.status_code == 201, planned.text
    body = planned.json()
    assert body["operation_job"]["executor"] == "artifact-mirror-worker"
    assert body["operation_plan"]["plan"]["runtime"]["state"] == "RUNTIME_CAPABLE"
    auth = _approve_and_authorize(client, body)
    executed = client.post(
        f"/v1/operation-jobs/{body['operation_job']['id']}/execute",
        headers=BOT,
        json={"execution_ticket": auth["execution_ticket"], "signature": auth["signature"], "actor": "hermes-bot:airgap"},
    )
    assert executed.status_code == 200, executed.text
    result = executed.json()
    assert result["operation_job"]["state"] == "SUCCEEDED"
    assert result["runtime_result"]["state"] == "MIRRORED"
    evidence = result["runtime_result"]["verification"]["evidence"]
    assert evidence["helm_oci_typed"] is True
    assert evidence["chart_layer_media_type"] == "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
    assert evidence["multi_arch"] == "not-applicable"

    retry = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={"requested_by": "hermes-bot:airgap-retry", "source_channel": "hermes-bot", "domain": "artifact", "operation": "artifact.mirror.apply", "target_id": created.json()["id"], "parameters": {"verify_destination": True}},
    ).json()
    retry_auth = _approve_and_authorize(client, retry)
    retried = client.post(
        f"/v1/operation-jobs/{retry['operation_job']['id']}/execute",
        headers=BOT,
        json={"execution_ticket": retry_auth["execution_ticket"], "signature": retry_auth["signature"], "actor": "hermes-bot:airgap-retry"},
    )
    assert retried.status_code == 200, retried.text
    assert retried.json()["runtime_result"]["state"] == "ALREADY_MIRRORED"
    assert sum(1 for call in calls if len(call) > 1 and call[1] == "copy") == 1


def test_helm_oci_registry_mirror_rejects_non_helm_manifest_and_non_semver_tag(client: TestClient, monkeypatch):
    image_manifest = b'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json"},"layers":[]}'
    digest = _digest(image_manifest)
    monkeypatch.setenv("HERMES_ARTIFACT_OCI_SOURCE_REGISTRY_ALLOWLIST", "registry.example")
    monkeypatch.setenv("HERMES_ARTIFACT_OCI_DESTINATION_REGISTRY_ALLOWLIST", "mirror.local")

    def fake_run(command, **kwargs):
        if command[1] == "inspect" and command[-1].startswith("docker://registry.example/"):
            return subprocess.CompletedProcess(command, 0, stdout=image_manifest, stderr=b"")
        raise AssertionError(command)

    monkeypatch.setattr(artifact_mirror.subprocess, "run", fake_run)
    bad_media = client.post(
        "/v1/artifact-mirror/items",
        headers=ADMIN,
        json={"name": "not-a-chart", "kind": "helm-chart", "source": "oci://registry.example/charts/cilium", "destination": "oci://mirror.local/charts/cilium", "version": "1.18.1", "digest": digest},
    ).json()
    planned = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={"requested_by": "hermes-bot:airgap", "source_channel": "hermes-bot", "domain": "artifact", "operation": "artifact.mirror.apply", "target_id": bad_media["id"], "parameters": {"verify_destination": True}},
    ).json()
    auth = _approve_and_authorize(client, planned)
    executed = client.post(
        f"/v1/operation-jobs/{planned['operation_job']['id']}/execute",
        headers=BOT,
        json={"execution_ticket": auth["execution_ticket"], "signature": auth["signature"], "actor": "hermes-bot:airgap"},
    )
    assert executed.status_code == 200, executed.text
    assert executed.json()["runtime_result"]["state"] == "FAILED"
    assert "Helm config media type" in executed.json()["runtime_result"]["verification"]["checks"][0]["summary"]

    bad_tag = client.post(
        "/v1/artifact-mirror/items",
        headers=ADMIN,
        json={"name": "bad-version", "kind": "helm-chart", "source": "oci://registry.example/charts/cilium", "destination": "oci://mirror.local/charts/cilium", "version": "latest", "digest": digest},
    ).json()
    bad_plan = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={"requested_by": "hermes-bot:airgap", "source_channel": "hermes-bot", "domain": "artifact", "operation": "artifact.mirror.apply", "target_id": bad_tag["id"], "parameters": {"verify_destination": True}},
    ).json()
    bad_auth = _approve_and_authorize(client, bad_plan)
    bad_execute = client.post(
        f"/v1/operation-jobs/{bad_plan['operation_job']['id']}/execute",
        headers=BOT,
        json={"execution_ticket": bad_auth["execution_ticket"], "signature": bad_auth["signature"], "actor": "hermes-bot:airgap"},
    )
    assert bad_execute.status_code == 200, bad_execute.text
    assert bad_execute.json()["runtime_result"]["state"] == "FAILED"
    assert "SemVer-compatible" in bad_execute.json()["runtime_result"]["verification"]["checks"][0]["summary"]
