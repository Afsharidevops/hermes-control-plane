from __future__ import annotations

import hashlib
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
COMMIT = "a" * 40
TAG = "refs/tags/v2.27.0"


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(app) as c:
        yield c


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _plan(client: TestClient, tmp_path: Path, digest: str, *, labels: dict[str, str] | None = None, source: str = "https://git.example/kubernetes-sigs/kubespray.git") -> dict:
    destination = tmp_path / "mirror" / "git" / "kubespray-v2.27.0.tar"
    destination.parent.mkdir(parents=True, exist_ok=True)
    created = client.post(
        "/v1/artifact-mirror/items",
        headers=ADMIN,
        json={
            "name": "kubespray-git-release",
            "kind": "git-release",
            "source": source,
            "destination": destination.as_uri(),
            "version": "v2.27.0",
            "digest": digest,
            "labels": labels or {"git_ref": TAG, "git_commit": COMMIT, "component": "provider:kubespray"},
        },
    )
    assert created.status_code == 201, created.text
    planned = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={
            "requested_by": "hermes-bot:airgap-git",
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
    assert body["operation_plan"]["plan"]["runtime"]["mode"] == "git-release-exact-tag-archive"
    expected_labels = labels or {"git_ref": TAG, "git_commit": COMMIT, "component": "provider:kubespray"}
    assert body["operation_plan"]["plan"]["artifact"]["labels"] == {key: expected_labels[key] for key in ("git_ref", "git_commit") if key in expected_labels}
    return body


def _authorize(client: TestClient, body: dict) -> dict:
    changeset = body["changeset"]
    requested = client.post(f"/v1/changesets/{changeset['id']}/request-approval", headers=BOT)
    assert requested.status_code == 200, requested.text
    approved = client.post(
        f"/v1/changesets/{changeset['id']}/approve",
        headers=APPROVAL,
        json={"approver": "approval-bot:git-release", "plan_hash": changeset["plan_hash"]},
    )
    assert approved.status_code == 201, approved.text
    authorized = client.post(f"/v1/operation-jobs/{body['operation_job']['id']}/authorize", headers=BOT)
    assert authorized.status_code == 200, authorized.text
    return authorized.json()


def _execute(client: TestClient, body: dict, auth: dict) -> dict:
    response = client.post(
        f"/v1/operation-jobs/{body['operation_job']['id']}/execute",
        headers=BOT,
        json={"execution_ticket": auth["execution_ticket"], "signature": auth["signature"], "actor": "hermes-bot:git-release"},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_git_release_exact_tag_archive_is_digest_verified_and_idempotent(client: TestClient, tmp_path: Path, monkeypatch):
    archive = b"canonical-kubespray-release-tar\n"
    digest = _digest(archive)
    mirror_root = tmp_path / "mirror"
    mirror_root.mkdir()
    monkeypatch.setenv("HERMES_ARTIFACT_MIRROR_ROOT", str(mirror_root))
    monkeypatch.setenv("HERMES_ARTIFACT_HTTPS_HOST_ALLOWLIST", "git.example")

    calls: list[list[str]] = []

    def fake_git(args, **kwargs):
        calls.append(list(args))
        if args[0] == "ls-remote":
            return subprocess.CompletedProcess(args, 0, stdout=f"{COMMIT}\t{TAG}\n".encode(), stderr=b"")
        if args[0] == "init":
            Path(args[-1]).mkdir(parents=True, exist_ok=True)
            return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")
        if "fetch" in args:
            assert "--depth=1" in args
            assert "--no-tags" in args
            assert args[-1] == f"+{TAG}:{TAG}"
            return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")
        if "rev-parse" in args:
            return subprocess.CompletedProcess(args, 0, stdout=(COMMIT + "\n").encode(), stderr=b"")
        if "cat-file" in args:
            return subprocess.CompletedProcess(args, 1, stdout=b"", stderr=b"")
        if "archive" in args:
            output = next(item.split("=", 1)[1] for item in args if item.startswith("--output="))
            Path(output).write_bytes(archive)
            return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")
        raise AssertionError(args)

    monkeypatch.setattr(artifact_mirror, "_run_git", fake_git)
    body = _plan(client, tmp_path, digest)
    result = _execute(client, body, _authorize(client, body))
    assert result["operation_job"]["state"] == "SUCCEEDED"
    assert result["runtime_result"]["state"] == "MIRRORED"
    assert result["runtime_result"]["verification"]["evidence"]["git_commit"] == COMMIT
    assert result["runtime_result"]["verification"]["evidence"]["credential_helpers_disabled"] is True
    assert result["verification"]["status"] == "PASS"

    destination = mirror_root / "git" / "kubespray-v2.27.0.tar"
    assert destination.read_bytes() == archive
    first_call_count = len(calls)

    second = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={
            "requested_by": "hermes-bot:airgap-git-retry",
            "source_channel": "hermes-bot",
            "domain": "artifact",
            "operation": "artifact.mirror.apply",
            "target_id": body["operation_plan"]["subject_id"],
            "parameters": {"verify_destination": True},
        },
    ).json()
    retried = _execute(client, second, _authorize(client, second))
    assert retried["runtime_result"]["state"] == "ALREADY_MIRRORED"
    assert len(calls) == first_call_count


def test_git_release_rejects_tag_commit_drift_before_fetch(client: TestClient, tmp_path: Path, monkeypatch):
    archive = b"release"
    mirror_root = tmp_path / "mirror"
    mirror_root.mkdir()
    monkeypatch.setenv("HERMES_ARTIFACT_MIRROR_ROOT", str(mirror_root))
    monkeypatch.setenv("HERMES_ARTIFACT_HTTPS_HOST_ALLOWLIST", "git.example")

    observed = "b" * 40
    calls: list[list[str]] = []

    def fake_git(args, **kwargs):
        calls.append(list(args))
        assert args[0] == "ls-remote"
        return subprocess.CompletedProcess(args, 0, stdout=f"{observed}\t{TAG}\n".encode(), stderr=b"")

    monkeypatch.setattr(artifact_mirror, "_run_git", fake_git)
    body = _plan(client, tmp_path, _digest(archive))
    result = _execute(client, body, _authorize(client, body))
    assert result["runtime_result"]["state"] == "FAILED"
    check = result["runtime_result"]["verification"]["checks"][0]
    assert check["id"] == "git-source-commit"
    assert check["evidence"]["expected_commit"] == COMMIT
    assert check["evidence"]["observed_commit"] == observed
    assert len(calls) == 1


def test_git_release_rejects_unsafe_binding_and_unallowlisted_source(client: TestClient, tmp_path: Path, monkeypatch):
    mirror_root = tmp_path / "mirror"
    mirror_root.mkdir()
    monkeypatch.setenv("HERMES_ARTIFACT_MIRROR_ROOT", str(mirror_root))
    monkeypatch.setenv("HERMES_ARTIFACT_HTTPS_HOST_ALLOWLIST", "git.example")

    unsafe = _plan(client, tmp_path, _digest(b"x"), labels={"git_ref": "refs/heads/main", "git_commit": COMMIT})
    unsafe_result = _execute(client, unsafe, _authorize(client, unsafe))
    assert unsafe_result["runtime_result"]["state"] == "FAILED"
    assert "refs/tags" in unsafe_result["runtime_result"]["verification"]["checks"][0]["summary"]

    # Use a new DB fixture row name by creating directly with a distinct item name.
    created = client.post(
        "/v1/artifact-mirror/items",
        headers=ADMIN,
        json={
            "name": "evil-git-release",
            "kind": "git-release",
            "source": "https://evil.example/org/repo.git",
            "destination": (mirror_root / "evil.tar").as_uri(),
            "version": "v2.27.0",
            "digest": _digest(b"x"),
            "labels": {"git_ref": TAG, "git_commit": COMMIT},
        },
    )
    assert created.status_code == 201
    planned = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={"requested_by": "hermes-bot:git", "source_channel": "hermes-bot", "domain": "artifact", "operation": "artifact.mirror.apply", "target_id": created.json()["id"], "parameters": {"verify_destination": True}},
    ).json()
    result = _execute(client, planned, _authorize(client, planned))
    assert result["runtime_result"]["state"] == "FAILED"
    assert "allowlisted" in result["runtime_result"]["verification"]["checks"][0]["summary"]


def test_git_release_rejects_submodule_archives(client: TestClient, tmp_path: Path, monkeypatch):
    archive = b"release"
    mirror_root = tmp_path / "mirror"
    mirror_root.mkdir()
    monkeypatch.setenv("HERMES_ARTIFACT_MIRROR_ROOT", str(mirror_root))
    monkeypatch.setenv("HERMES_ARTIFACT_HTTPS_HOST_ALLOWLIST", "git.example")

    def fake_git(args, **kwargs):
        if args[0] == "ls-remote":
            return subprocess.CompletedProcess(args, 0, stdout=f"{COMMIT}\t{TAG}\n".encode(), stderr=b"")
        if args[0] == "init":
            Path(args[-1]).mkdir(parents=True, exist_ok=True)
            return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")
        if "fetch" in args:
            return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")
        if "rev-parse" in args:
            return subprocess.CompletedProcess(args, 0, stdout=(COMMIT + "\n").encode(), stderr=b"")
        if "cat-file" in args:
            return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")
        raise AssertionError(args)

    monkeypatch.setattr(artifact_mirror, "_run_git", fake_git)
    body = _plan(client, tmp_path, _digest(archive))
    result = _execute(client, body, _authorize(client, body))
    assert result["runtime_result"]["state"] == "FAILED"
    assert ".gitmodules" in result["runtime_result"]["verification"]["checks"][0]["summary"]


def test_git_release_network_retry_is_bounded(client: TestClient, tmp_path: Path, monkeypatch):
    archive = b"retryable-release\n"
    mirror_root = tmp_path / "mirror"
    mirror_root.mkdir()
    monkeypatch.setenv("HERMES_ARTIFACT_MIRROR_ROOT", str(mirror_root))
    monkeypatch.setenv("HERMES_ARTIFACT_HTTPS_HOST_ALLOWLIST", "git.example")
    attempts = {"ls_remote": 0}

    def fake_git(args, **kwargs):
        if args[0] == "ls-remote":
            attempts["ls_remote"] += 1
            if attempts["ls_remote"] == 1:
                raise artifact_mirror.ArtifactMirrorError("transient Git release operation failure")
            return subprocess.CompletedProcess(args, 0, stdout=f"{COMMIT}\t{TAG}\n".encode(), stderr=b"")
        if args[0] == "init":
            Path(args[-1]).mkdir(parents=True, exist_ok=True)
            return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")
        if "fetch" in args:
            return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")
        if "rev-parse" in args:
            return subprocess.CompletedProcess(args, 0, stdout=(COMMIT + "\n").encode(), stderr=b"")
        if "cat-file" in args:
            return subprocess.CompletedProcess(args, 1, stdout=b"", stderr=b"")
        if "archive" in args:
            output = next(item.split("=", 1)[1] for item in args if item.startswith("--output="))
            Path(output).write_bytes(archive)
            return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")
        raise AssertionError(args)

    monkeypatch.setattr(artifact_mirror, "_run_git", fake_git)
    body = _plan(client, tmp_path, _digest(archive))
    result = _execute(client, body, _authorize(client, body))
    assert result["runtime_result"]["state"] == "MIRRORED"
    assert result["runtime_result"]["verification"]["evidence"]["network_attempt_limit"] == 2
    assert attempts["ls_remote"] == 2
