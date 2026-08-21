from __future__ import annotations

import gzip
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

from hermes_control_plane import artifact_mirror, db  # noqa: E402
from hermes_control_plane.main import app  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin"}
BOT = {"Authorization": "Bearer test-bot"}
APPROVAL = {"Authorization": "Bearer test-approval"}
VERSION = "2026.08.21"


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(app) as c:
        yield c


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest(data: bytes) -> str:
    return "sha256:" + _sha(data)


def _snapshot(kind: str, repository_id: str, files: dict[str, bytes], *, version: str = VERSION) -> bytes:
    manifest = {
        "schema_version": 1,
        "kind": kind,
        "repository_id": repository_id,
        "version": version,
        "files": [
            {"path": name, "sha256": _sha(data), "size": len(data)}
            for name, data in sorted(files.items())
        ],
    }
    manifest_raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, data in [("HERMES-REPOSITORY-SNAPSHOT.json", manifest_raw), *sorted(files.items())]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


def _apt_snapshot(*, tamper_deb: bool = False) -> bytes:
    deb = b"fake-deb-package-v1\n"
    package_digest = _sha(deb)
    packages = (
        "Package: kubeadm\n"
        "Version: 1.34.0-1\n"
        "Architecture: amd64\n"
        "Filename: pool/main/k/kubeadm/kubeadm_1.34.0-1_amd64.deb\n"
        f"Size: {len(deb)}\n"
        f"SHA256: {package_digest}\n\n"
    ).encode()
    packages_gz = gzip.compress(packages, mtime=0)
    release = (
        "Suite: stable\n"
        "Codename: stable\n"
        "Components: main\n"
        "Architectures: amd64\n"
        "Date: Fri, 21 Aug 2026 00:00:00 UTC\n"
        "SHA256:\n"
        f" {_sha(packages_gz)} {len(packages_gz)} main/binary-amd64/Packages.gz\n"
    ).encode()
    files = {
        "dists/stable/Release": release,
        "dists/stable/Release.gpg": b"fake-detached-signature",
        "dists/stable/main/binary-amd64/Packages.gz": packages_gz,
        "pool/main/k/kubeadm/kubeadm_1.34.0-1_amd64.deb": b"tampered" if tamper_deb else deb,
    }
    return _snapshot("apt-repository", "kubernetes-apt", files)


def _rpm_snapshot() -> bytes:
    rpm = b"fake-rpm-package-v1\n"
    rpm_digest = _sha(rpm)
    primary = f'''<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" packages="1">
  <package type="rpm">
    <name>kubelet</name>
    <arch>x86_64</arch>
    <version epoch="0" ver="1.34.0" rel="1"/>
    <checksum type="sha256" pkgid="YES">{rpm_digest}</checksum>
    <size package="{len(rpm)}" installed="1" archive="1"/>
    <location href="Packages/kubelet-1.34.0-1.x86_64.rpm"/>
  </package>
</metadata>
'''.encode()
    primary_gz = gzip.compress(primary, mtime=0)
    primary_name = f"repodata/{_sha(primary_gz)}-primary.xml.gz"
    repomd = f'''<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <revision>20260821</revision>
  <data type="primary">
    <checksum type="sha256">{_sha(primary_gz)}</checksum>
    <location href="{primary_name}"/>
    <size>{len(primary_gz)}</size>
  </data>
</repomd>
'''.encode()
    return _snapshot(
        "rpm-repository",
        "kubernetes-rpm",
        {
            "repodata/repomd.xml": repomd,
            "repodata/repomd.xml.asc": b"fake-detached-signature",
            primary_name: primary_gz,
            "Packages/kubelet-1.34.0-1.x86_64.rpm": rpm,
        },
    )


def _python_snapshot(*, bad_hash: bool = False) -> bytes:
    wheel_name = "kubernetes-34.1.0-py2.py3-none-any.whl"
    wheel = b"fake-wheel-v1\n"
    project = (
        '<!doctype html><html><body>'
        f'<a href="../../packages/{wheel_name}#sha256={("0" * 64) if bad_hash else _sha(wheel)}">{wheel_name}</a>'
        '</body></html>'
    ).encode()
    root_index = b'<!doctype html><html><body><a href="kubernetes/">kubernetes</a></body></html>'
    return _snapshot(
        "python-repository",
        "python-offline",
        {
            "simple/index.html": root_index,
            "simple/kubernetes/index.html": project,
            f"packages/{wheel_name}": wheel,
        },
    )


def _plan(client: TestClient, tmp_path: Path, *, kind: str, archive: bytes, repository_id: str, labels: dict[str, str], replace_existing: bool = False, name_suffix: str = "") -> tuple[dict, Path]:
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    source_root.mkdir(exist_ok=True)
    mirror_root.mkdir(exist_ok=True)
    source = source_root / f"{repository_id}.tar.gz"
    source.write_bytes(archive)
    destination = mirror_root / "repositories" / repository_id
    created = client.post(
        "/v1/artifact-mirror/items",
        headers=ADMIN,
        json={
            "name": f"{repository_id}-{kind}{name_suffix}",
            "kind": kind,
            "source": source.as_uri(),
            "destination": destination.as_uri(),
            "version": VERSION,
            "digest": _digest(archive),
            "labels": {"repository_id": repository_id, **labels},
        },
    )
    assert created.status_code == 201, created.text
    planned = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={
            "requested_by": "hermes-bot:repo-snapshot",
            "source_channel": "hermes-bot",
            "domain": "artifact",
            "operation": "artifact.mirror.apply",
            "target_id": created.json()["id"],
            "parameters": {"verify_destination": True, "replace_existing": replace_existing},
        },
    )
    assert planned.status_code == 201, planned.text
    body = planned.json()
    assert body["operation_job"]["executor"] == "artifact-mirror-worker"
    assert body["operation_plan"]["plan"]["runtime"]["mode"] == f"{kind}-snapshot"
    return body, destination


def _authorize_execute(client: TestClient, body: dict) -> dict:
    changeset = body["changeset"]
    assert client.post(f"/v1/changesets/{changeset['id']}/request-approval", headers=BOT).status_code == 200
    approved = client.post(
        f"/v1/changesets/{changeset['id']}/approve",
        headers=APPROVAL,
        json={"approver": "approval-bot:repository", "plan_hash": changeset["plan_hash"]},
    )
    assert approved.status_code == 201, approved.text
    authorized = client.post(f"/v1/operation-jobs/{body['operation_job']['id']}/authorize", headers=BOT)
    assert authorized.status_code == 200, authorized.text
    auth = authorized.json()
    executed = client.post(
        f"/v1/operation-jobs/{body['operation_job']['id']}/execute",
        headers=BOT,
        json={"execution_ticket": auth["execution_ticket"], "signature": auth["signature"], "actor": "hermes-bot:repository"},
    )
    assert executed.status_code == 200, executed.text
    return executed.json()


def _runtime_env(monkeypatch, tmp_path: Path):
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    auth_root = tmp_path / "auth"
    source_root.mkdir(exist_ok=True)
    mirror_root.mkdir(exist_ok=True)
    auth_root.mkdir(exist_ok=True)
    keyring = auth_root / "repositories.gpg"
    keyring.write_bytes(b"trusted-keyring-fixture")
    monkeypatch.setenv("HERMES_ARTIFACT_SOURCE_ROOT", str(source_root))
    monkeypatch.setenv("HERMES_ARTIFACT_MIRROR_ROOT", str(mirror_root))
    monkeypatch.setenv("HERMES_ARTIFACT_AUTH_ROOT", str(auth_root))
    monkeypatch.setenv("HERMES_ARTIFACT_REPOSITORY_KEYRING", str(keyring))
    monkeypatch.setattr(artifact_mirror, "_verify_repository_signature", lambda data, signature: None)


def test_apt_repository_snapshot_verifies_release_index_packages_and_is_idempotent(client: TestClient, tmp_path: Path, monkeypatch):
    _runtime_env(monkeypatch, tmp_path)
    archive = _apt_snapshot()
    body, destination = _plan(
        client,
        tmp_path,
        kind="apt-repository",
        archive=archive,
        repository_id="kubernetes-apt",
        labels={"signature_policy": "required", "apt_distribution": "stable", "apt_components": "main", "apt_architectures": "amd64", "component": "provider:kubespray"},
    )
    result = _authorize_execute(client, body)
    assert result["operation_job"]["state"] == "SUCCEEDED"
    assert result["runtime_result"]["state"] == "MIRRORED"
    evidence = result["runtime_result"]["verification"]["evidence"]
    assert evidence["repository_format"] == "apt"
    assert evidence["release_signature_verified"] is True
    assert evidence["verified_packages"] == 1
    assert evidence["partial_sync_recovery"] == "atomic-staging-with-rollback"
    assert (destination / "dists/stable/Release").is_file()
    assert (destination / ".hermes-repository-snapshot.json").is_file()

    item_id = body["operation_plan"]["subject_id"]
    retry = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={"requested_by": "hermes-bot:repo-retry", "source_channel": "hermes-bot", "domain": "artifact", "operation": "artifact.mirror.apply", "target_id": item_id, "parameters": {"verify_destination": True}},
    )
    assert retry.status_code == 201, retry.text
    second = _authorize_execute(client, retry.json())
    assert second["runtime_result"]["state"] == "ALREADY_MIRRORED"


def test_rpm_repository_snapshot_verifies_signed_repomd_primary_and_packages(client: TestClient, tmp_path: Path, monkeypatch):
    _runtime_env(monkeypatch, tmp_path)
    body, destination = _plan(
        client,
        tmp_path,
        kind="rpm-repository",
        archive=_rpm_snapshot(),
        repository_id="kubernetes-rpm",
        labels={"signature_policy": "required", "component": "provider:kubespray"},
    )
    result = _authorize_execute(client, body)
    assert result["operation_job"]["state"] == "SUCCEEDED"
    evidence = result["runtime_result"]["verification"]["evidence"]
    assert evidence["repository_format"] == "rpm"
    assert evidence["repomd_signature_verified"] is True
    assert evidence["verified_packages"] == 1
    assert (destination / "repodata/repomd.xml").is_file()


def test_python_repository_snapshot_verifies_pep503_sha256_links(client: TestClient, tmp_path: Path, monkeypatch):
    _runtime_env(monkeypatch, tmp_path)
    body, destination = _plan(
        client,
        tmp_path,
        kind="python-repository",
        archive=_python_snapshot(),
        repository_id="python-offline",
        labels={"signature_policy": "pep503-sha256", "component": "provider:kubespray"},
    )
    result = _authorize_execute(client, body)
    assert result["operation_job"]["state"] == "SUCCEEDED"
    evidence = result["runtime_result"]["verification"]["evidence"]
    assert evidence["repository_format"] == "python-simple"
    assert evidence["verified_distributions"] == 1
    assert evidence["raw_credentials_returned"] is False
    assert (destination / "simple/kubernetes/index.html").is_file()


def test_apt_repository_rejects_package_tamper_without_publishing_destination(client: TestClient, tmp_path: Path, monkeypatch):
    _runtime_env(monkeypatch, tmp_path)
    archive = _apt_snapshot(tamper_deb=True)
    body, destination = _plan(
        client,
        tmp_path,
        kind="apt-repository",
        archive=archive,
        repository_id="kubernetes-apt",
        labels={"signature_policy": "required", "apt_distribution": "stable", "apt_components": "main", "apt_architectures": "amd64"},
    )
    result = _authorize_execute(client, body)
    assert result["operation_job"]["state"] == "FAILED"
    assert result["verification"]["status"] == "FAIL"
    assert not destination.exists()
    assert "checksum/size mismatch" in result["runtime_result"]["verification"]["checks"][0]["summary"]


def test_repository_signature_policy_is_fail_closed(client: TestClient, tmp_path: Path, monkeypatch):
    _runtime_env(monkeypatch, tmp_path)
    body, destination = _plan(
        client,
        tmp_path,
        kind="rpm-repository",
        archive=_rpm_snapshot(),
        repository_id="kubernetes-rpm",
        labels={"signature_policy": "required"},
    )
    monkeypatch.setattr(artifact_mirror, "_verify_repository_signature", lambda data, signature: (_ for _ in ()).throw(artifact_mirror.ArtifactMirrorError("repository signature verification failed with exit code 2")))
    result = _authorize_execute(client, body)
    assert result["operation_job"]["state"] == "FAILED"
    assert not destination.exists()
    assert "signature verification failed" in result["runtime_result"]["verification"]["checks"][0]["summary"]


def test_https_authfile_is_host_scoped_and_not_returned(monkeypatch, tmp_path: Path):
    auth_root = tmp_path / "auth"
    auth_root.mkdir()
    authfile = auth_root / "https.json"
    authfile.write_text(json.dumps({"repo.example": {"authorization": "Bearer super-secret-token"}}), encoding="utf-8")
    monkeypatch.setenv("HERMES_ARTIFACT_AUTH_ROOT", str(auth_root))
    monkeypatch.setenv("HERMES_ARTIFACT_HTTPS_AUTHFILE", str(authfile))
    assert artifact_mirror._https_authorization_header("https://repo.example/snapshot.tar.gz") == "Bearer super-secret-token"
    assert artifact_mirror._https_authorization_header("https://other.example/snapshot.tar.gz") is None
    capability = artifact_mirror.runtime_capability("https://repo.example/snapshot.tar.gz", "file:///data/artifact-mirror/repo", kind="apt-repository")
    assert "super-secret-token" not in json.dumps(capability)
    assert "environment-mounted" in capability["credential_delivery"]


def test_dev_branch_push_keeps_validate_but_does_not_publish_images():
    root = Path(__file__).resolve().parents[2]
    publish = (root / ".github/workflows/publish-images.yml").read_text(encoding="utf-8")
    validate = (root / ".github/workflows/validate.yml").read_text(encoding="utf-8")
    assert "branches: [main]" in publish
    assert "'dev/**'" not in publish
    assert "pull_request:" not in publish
    assert "'dev/**'" in validate
    assert "pull_request:" in validate
    assert 'tags: ["v*"]' in publish
    assert "workflow_dispatch:" in publish

def test_repository_replacement_failure_preserves_previous_verified_tree(client: TestClient, tmp_path: Path, monkeypatch):
    _runtime_env(monkeypatch, tmp_path)
    valid, destination = _plan(
        client, tmp_path, kind="python-repository", archive=_python_snapshot(), repository_id="python-offline",
        labels={"signature_policy": "pep503-sha256"},
    )
    first = _authorize_execute(client, valid)
    assert first["operation_job"]["state"] == "SUCCEEDED"
    marker_before = (destination / ".hermes-repository-snapshot.json").read_bytes()
    index_before = (destination / "simple/kubernetes/index.html").read_bytes()

    invalid, same_destination = _plan(
        client, tmp_path, kind="python-repository", archive=_python_snapshot(bad_hash=True), repository_id="python-offline",
        labels={"signature_policy": "pep503-sha256"}, replace_existing=True, name_suffix="-replacement",
    )
    assert same_destination == destination
    failed = _authorize_execute(client, invalid)
    assert failed["operation_job"]["state"] == "FAILED"
    assert destination.is_dir()
    assert (destination / ".hermes-repository-snapshot.json").read_bytes() == marker_before
    assert (destination / "simple/kubernetes/index.html").read_bytes() == index_before
