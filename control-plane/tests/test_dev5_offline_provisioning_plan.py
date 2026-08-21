from __future__ import annotations

import json
import os
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ["HERMES_CONTROL_ADMIN_TOKEN"] = "test-admin"
os.environ["HERMES_BOT_SERVICE_TOKEN"] = "test-bot"
os.environ["HERMES_CREDENTIAL_SERVICE_TOKEN"] = "test-credential-service"
os.environ["HERMES_APPROVAL_BOT_TOKEN"] = "test-approval"
os.environ["HERMES_APPROVAL_HMAC_KEY"] = "approval-hmac-key-0123456789abcdef0123456789abcdef"

from hermes_control_plane import cluster_factory, db  # noqa: E402
from hermes_control_plane.main import app  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin"}
BOT = {"Authorization": "Bearer test-bot"}
CREDENTIAL_SERVICE = {"Authorization": "Bearer test-credential-service"}
APPROVAL = {"Authorization": "Bearer test-approval"}
FP = "SHA256:" + "C" * 43


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(app) as c:
        yield c


def _artifact(client: TestClient, *, name: str, component: str, component_name: str, version: str, key: str, index: int) -> dict:
    response = client.post(
        "/v1/artifact-mirror/items",
        headers=ADMIN,
        json={
            "name": name,
            "kind": "helm-chart" if component == "addon" else "package",
            "source": f"https://source.example/{name}",
            "destination": f"file:///srv/hermes-mirror/{name}",
            "version": version,
            "digest": "sha256:" + format(index, "064x"),
            "labels": {
                "blueprint_component": component,
                "blueprint_name": component_name,
                "dependency_key": key,
            },
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _mark_mirrored(artifact_id: str) -> None:
    verification = {
        "verification_id": f"ver_{artifact_id[4:]}",
        "status": "PASS",
        "sync_state": "MIRRORED",
        "checks": [{"id": "destination-digest", "status": "PASS"}],
        "observed_at": 1770000000,
    }
    with closing(db.connect()) as conn:
        conn.execute(
            "UPDATE artifact_mirror_items SET verification_json=? WHERE id=?",
            (json.dumps(verification, sort_keys=True), artifact_id),
        )
        conn.commit()


def _offline_cluster(client: TestClient, *, leave_unmirrored: str | None = None) -> tuple[dict, dict, list[dict]]:
    env = client.post("/v1/environments", headers=ADMIN, json={"name": "Offline", "risk_level": "HIGH"}).json()
    cred = client.post(
        "/v1/internal/credential-refs/sync",
        headers=CREDENTIAL_SERVICE,
        json={
            "id": "cred_dev5offline1",
            "name": "offline-ssh",
            "kind": "ssh-key",
            "provider": "local-encrypted",
            "status": "configured",
            "metadata": {"backend": "local-encrypted", "fingerprint": "sha256:" + "d" * 64, "version": 1},
        },
    ).json()
    server = client.post(
        "/v1/servers",
        headers=ADMIN,
        json={
            "hostname": "offline-cp01.example.internal",
            "environment_id": env["id"],
            "management_ip": "10.70.0.11",
            "host_fingerprint": FP,
            "connection_mode": "agent",
            "credential_ref": cred["id"],
        },
    ).json()
    preflight = client.post(f"/v1/servers/{server['id']}/preflight-plan", headers=ADMIN).json()
    recorded = client.post(
        f"/v1/servers/{server['id']}/preflight-result",
        headers=ADMIN,
        json={
            "provider_job_id": preflight["provider_job_id"],
            "status": "PASS",
            "summary": "offline node passed fixed SSH preflight",
            "checks": [{"id": "ssh-connectivity", "status": "PASS"}],
            "facts": {"os": "ubuntu", "cpu_count": 8},
        },
    )
    assert recorded.status_code == 200, recorded.text

    artifacts = [
        _artifact(client, name="kubespray-offline", component="provider", component_name="kubespray", version="2.28.1", key="provider", index=101),
        _artifact(client, name="kubernetes-offline", component="kubernetes", component_name="kubernetes", version="1.35.6", key="packages", index=102),
        _artifact(client, name="cilium-offline", component="addon", component_name="cilium", version="1.19.4", key="chart", index=103),
        _artifact(client, name="agent-offline", component="addon", component_name="hermes-agent", version="0.5.11-dev.5", key="chart", index=104),
    ]
    for item in artifacts:
        if item["name"] != leave_unmirrored:
            _mark_mirrored(item["id"])

    blueprint_response = client.post(
        "/v1/cluster-blueprints",
        headers=ADMIN,
        json={
            "name": "offline-provisioning-blueprint",
            "provider": "kubespray",
            "provider_version": "2.28.1",
            "kubernetes_version": "1.35.6",
            "network_plugin": "cilium",
            "hubble_enabled": False,
            "radar_enabled": False,
            "addon_defaults": [],
            "addon_versions": {"cilium": "1.19.4", "hermes-agent": "0.5.11-dev.5"},
            "artifact_dependencies": [item["id"] for item in artifacts],
        },
    )
    assert blueprint_response.status_code == 201, blueprint_response.text
    blueprint = blueprint_response.json()
    profile = client.post(
        "/v1/cluster-profiles",
        headers=ADMIN,
        json={
            "name": "offline-profile",
            "environment_id": env["id"],
            "blueprint_id": blueprint["id"],
            "server_ids": [server["id"]],
        },
    ).json()
    role = client.post(
        "/v1/node-roles",
        headers=ADMIN,
        json={"profile_id": profile["id"], "role": "control-plane-worker", "server_ids": [server["id"]]},
    )
    assert role.status_code == 201, role.text
    cluster = client.post(
        "/v1/clusters",
        headers=ADMIN,
        json={"name": "offline-cluster", "environment_id": env["id"], "profile_id": profile["id"]},
    )
    assert cluster.status_code == 201, cluster.text
    return cluster.json(), blueprint, artifacts


def test_ready_artifact_manifest_is_bound_into_changeset_and_provider_job(client: TestClient):
    cluster, blueprint, _ = _offline_cluster(client)
    manifest = client.get(f"/v1/cluster-blueprints/{blueprint['id']}/artifact-manifest", headers=ADMIN).json()
    assert manifest["state"] == "READY"

    response = client.post(
        f"/v1/clusters/{cluster['id']}/provisioning-runs",
        headers=BOT,
        json={"requested_by": "hermes-bot:offline-test", "source_channel": "hermes-bot"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    supply = body["plan"]["artifact_supply"]
    assert supply["mode"] == "offline-manifest-bound"
    assert supply["manifest_hash"] == manifest["manifest_hash"]
    assert supply["credential_material_in_plan"] is False
    assert supply["provisioner_rewrite_applied"] is False
    assert len(supply["dependency_order"]) == 4
    assert all(item["offline_reference"].startswith("file:///srv/hermes-mirror/") for item in supply["dependency_order"])
    assert all("source" not in item and "labels" not in item and "verification" not in item for item in supply["dependency_order"])
    assert body["plan"]["provider_payload"]["offline_artifact_manifest_hash"] == manifest["manifest_hash"]
    assert body["changeset"]["parameters"]["artifact_manifest_hash"] == manifest["manifest_hash"]

    job = client.get(f"/v1/provider-jobs/{body['provider_job_ids'][0]}", headers=ADMIN).json()
    assert job["request"]["artifact_manifest_hash"] == manifest["manifest_hash"]
    assert job["request"]["offline_artifacts"] == supply["dependency_order"]
    serialized = json.dumps(job["request"], sort_keys=True)
    assert "source.example" not in serialized
    assert "credential_ref" not in serialized


def test_blocked_artifact_manifest_prevents_provisioning_run_creation(client: TestClient):
    cluster, _, _ = _offline_cluster(client, leave_unmirrored="kubernetes-offline")
    response = client.post(
        f"/v1/clusters/{cluster['id']}/provisioning-runs",
        headers=BOT,
        json={"requested_by": "hermes-bot:offline-test", "source_channel": "hermes-bot"},
    )
    assert response.status_code == 409, response.text
    assert "artifact manifest must be READY" in response.json()["detail"]
    with closing(db.connect()) as conn:
        assert conn.execute("SELECT COUNT(*) FROM provisioning_runs").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM provider_jobs WHERE operation='cluster.provision.apply'").fetchone()[0] == 0



def test_artifact_manifest_drift_blocks_provider_job_authorization(client: TestClient):
    cluster, _, artifacts = _offline_cluster(client)
    response = client.post(
        f"/v1/clusters/{cluster['id']}/provisioning-runs",
        headers=BOT,
        json={"requested_by": "hermes-bot:offline-test", "source_channel": "hermes-bot"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    changeset = body["changeset"]
    assert client.post(f"/v1/changesets/{changeset['id']}/request-approval", headers=BOT).status_code == 200
    approved = client.post(
        f"/v1/changesets/{changeset['id']}/approve",
        headers=APPROVAL,
        json={"approver": "approval-bot:offline", "plan_hash": changeset["plan_hash"]},
    )
    assert approved.status_code == 201, approved.text

    with closing(db.connect()) as conn:
        verification = {"status": "FAIL", "sync_state": "FAILED", "checks": [], "observed_at": 1770000001}
        conn.execute(
            "UPDATE artifact_mirror_items SET verification_json=? WHERE id=?",
            (json.dumps(verification, sort_keys=True), artifacts[0]["id"]),
        )
        conn.commit()

    authorized = client.post(f"/v1/provider-jobs/{body['provider_job_ids'][0]}/authorize", headers=BOT)
    assert authorized.status_code == 409, authorized.text
    assert "artifact manifest drifted" in authorized.json()["detail"]

def test_artifact_manifest_hash_tampering_is_rejected_before_plan_binding():
    plan = {
        "schema_version": 3,
        "kind": "ClusterProvisioningPlan",
        "provider_payload": {"kind": "KubesprayExecutionSpec"},
        "plan_hash": "ignored",
    }
    manifest = {
        "schema_version": 1,
        "kind": "ClusterBlueprintArtifactManifest",
        "state": "READY",
        "issues": [],
        "dependency_order": [
            {
                "artifact_id": "art_0123456789abcdef",
                "component": "provider",
                "name": "kubespray",
                "dependency_key": "provider",
                "kind": "package",
                "version": "2.28.1",
                "digest": "sha256:" + "1" * 64,
                "offline_reference": "file:///srv/hermes-mirror/kubespray",
                "depends_on": [],
                "mirrored": True,
            }
        ],
        "offline_reference_selection": "verified-destination-only",
        "credential_material_in_manifest": False,
        "provisioner_rewrite_applied": False,
    }
    manifest["manifest_hash"] = cluster_factory.sha256_hex(manifest)
    manifest["dependency_order"][0]["offline_reference"] = "file:///srv/hermes-mirror/tampered"
    with pytest.raises(ValueError, match="manifest hash verification failed"):
        cluster_factory._bind_ready_artifact_manifest(plan, manifest)
