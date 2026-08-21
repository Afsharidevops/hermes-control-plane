from __future__ import annotations

import json
import os
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ["HERMES_CONTROL_ADMIN_TOKEN"] = "test-admin"

from hermes_control_plane import db  # noqa: E402
from hermes_control_plane.main import app  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin"}


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
            "kind": "package" if component != "addon" else "helm-chart",
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


def _set_labels(artifact_id: str, labels: dict[str, str]) -> None:
    with closing(db.connect()) as conn:
        conn.execute("UPDATE artifact_mirror_items SET labels_json=? WHERE id=?", (json.dumps(labels, sort_keys=True), artifact_id))
        conn.commit()


def _mark_mirrored(artifact_id: str, *, observed_at: int = 1770000000) -> None:
    verification = {
        "verification_id": f"ver_{artifact_id[4:]}",
        "status": "PASS",
        "sync_state": "MIRRORED",
        "checks": [{"id": "destination-digest", "status": "PASS"}],
        "observed_at": observed_at,
    }
    with closing(db.connect()) as conn:
        conn.execute("UPDATE artifact_mirror_items SET verification_json=? WHERE id=?", (json.dumps(verification, sort_keys=True), artifact_id))
        conn.commit()


def _blueprint(client: TestClient, artifact_ids: list[str]) -> dict:
    response = client.post(
        "/v1/cluster-blueprints",
        headers=ADMIN,
        json={
            "name": "airgap-blueprint",
            "provider": "kubespray",
            "provider_version": "2.28.1",
            "kubernetes_version": "1.35.6",
            "network_plugin": "cilium",
            "hubble_enabled": False,
            "radar_enabled": False,
            "addon_defaults": ["cert-manager"],
            "addon_versions": {
                "cilium": "1.19.4",
                "hermes-agent": "0.5.11-dev.5",
                "cert-manager": "1.18.2",
            },
            "artifact_dependencies": artifact_ids,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_blueprint_artifact_manifest_is_exact_ordered_and_credential_free(client: TestClient):
    provider = _artifact(client, name="kubespray-bundle", component="provider", component_name="kubespray", version="2.28.1", key="provider-bundle", index=1)
    kubernetes = _artifact(client, name="kubernetes-bundle", component="kubernetes", component_name="kubernetes", version="1.35.6", key="node-packages", index=2)
    cilium = _artifact(client, name="cilium-chart", component="addon", component_name="cilium", version="1.19.4", key="chart", index=3)
    agent = _artifact(client, name="hermes-agent-chart", component="addon", component_name="hermes-agent", version="0.5.11-dev.5", key="chart", index=4)
    cert_manager = _artifact(client, name="cert-manager-chart", component="addon", component_name="cert-manager", version="1.18.2", key="chart", index=5)

    _set_labels(kubernetes["id"], {**kubernetes["labels"], "depends_on": provider["id"]})
    _set_labels(cilium["id"], {**cilium["labels"], "depends_on": kubernetes["id"]})
    _set_labels(agent["id"], {**agent["labels"], "depends_on": kubernetes["id"]})
    _set_labels(cert_manager["id"], {**cert_manager["labels"], "depends_on": kubernetes["id"]})
    for item in (provider, kubernetes, cilium, agent, cert_manager):
        _mark_mirrored(item["id"])

    blueprint = _blueprint(client, [cert_manager["id"], cilium["id"], provider["id"], agent["id"], kubernetes["id"]])
    response = client.get(f"/v1/cluster-blueprints/{blueprint['id']}/artifact-manifest", headers=ADMIN)
    assert response.status_code == 200, response.text
    manifest = response.json()
    assert manifest["state"] == "READY"
    assert manifest["issues"] == []
    assert manifest["resume_from_artifact_id"] is None
    assert manifest["credential_material_in_manifest"] is False
    assert manifest["offline_reference_selection"] == "verified-destination-only"
    assert manifest["provisioner_rewrite_applied"] is False
    ordered_ids = [item["artifact_id"] for item in manifest["dependency_order"]]
    assert ordered_ids[0] == provider["id"]
    assert ordered_ids[1] == kubernetes["id"]
    assert set(ordered_ids[2:]) == {cilium["id"], agent["id"], cert_manager["id"]}
    assert all(item["offline_reference"].startswith("file:///srv/hermes-mirror/") for item in manifest["dependency_order"])
    assert all("source" not in item and "labels" not in item for item in manifest["dependency_order"])

    again = client.get(f"/v1/cluster-blueprints/{blueprint['id']}/artifact-manifest", headers=ADMIN).json()
    assert again["manifest_hash"] == manifest["manifest_hash"]
    assert again["dependency_order"] == manifest["dependency_order"]


def test_blueprint_artifact_manifest_blocks_missing_unmirrored_and_version_mismatch(client: TestClient):
    provider = _artifact(client, name="provider", component="provider", component_name="kubespray", version="2.28.1", key="provider", index=10)
    kubernetes = _artifact(client, name="kubernetes", component="kubernetes", component_name="kubernetes", version="1.34.0", key="packages", index=11)
    cilium = _artifact(client, name="cilium", component="addon", component_name="cilium", version="1.19.4", key="chart", index=12)
    _mark_mirrored(provider["id"])
    _mark_mirrored(cilium["id"])
    blueprint = _blueprint(client, [provider["id"], kubernetes["id"], cilium["id"]])

    manifest = client.get(f"/v1/cluster-blueprints/{blueprint['id']}/artifact-manifest", headers=ADMIN).json()
    assert manifest["state"] == "BLOCKED"
    codes = {issue["code"] for issue in manifest["issues"]}
    assert "version-mismatch" in codes
    assert "artifact-not-mirrored" in codes
    assert "missing-component" in codes
    assert manifest["resume_from_artifact_id"] == kubernetes["id"]


def test_blueprint_artifact_manifest_rejects_dependency_cycles(client: TestClient):
    provider = _artifact(client, name="provider-cycle", component="provider", component_name="kubespray", version="2.28.1", key="provider", index=20)
    kubernetes = _artifact(client, name="kubernetes-cycle", component="kubernetes", component_name="kubernetes", version="1.35.6", key="packages", index=21)
    cilium = _artifact(client, name="cilium-cycle", component="addon", component_name="cilium", version="1.19.4", key="chart", index=22)
    agent = _artifact(client, name="agent-cycle", component="addon", component_name="hermes-agent", version="0.5.11-dev.5", key="chart", index=23)
    cert_manager = _artifact(client, name="cert-cycle", component="addon", component_name="cert-manager", version="1.18.2", key="chart", index=24)
    _set_labels(provider["id"], {**provider["labels"], "depends_on": kubernetes["id"]})
    _set_labels(kubernetes["id"], {**kubernetes["labels"], "depends_on": provider["id"]})
    for item in (provider, kubernetes, cilium, agent, cert_manager):
        _mark_mirrored(item["id"])
    blueprint = _blueprint(client, [provider["id"], kubernetes["id"], cilium["id"], agent["id"], cert_manager["id"]])

    manifest = client.get(f"/v1/cluster-blueprints/{blueprint['id']}/artifact-manifest", headers=ADMIN).json()
    assert manifest["state"] == "BLOCKED"
    cycle = [issue for issue in manifest["issues"] if issue["code"] == "dependency-cycle"]
    assert len(cycle) == 1
    assert set(cycle[0]["artifact_ids"]) == {provider["id"], kubernetes["id"]}


def test_blueprint_artifact_dependency_binding_is_guarded(client: TestClient):
    artifact = _artifact(client, name="binding", component="provider", component_name="kubespray", version="2.28.1", key="provider", index=30)
    blueprint = _blueprint(client, [])

    duplicate = client.put(
        f"/v1/cluster-blueprints/{blueprint['id']}/artifact-dependencies",
        headers=ADMIN,
        json={"artifact_dependencies": [artifact["id"], artifact["id"]]},
    )
    assert duplicate.status_code == 422

    missing = client.put(
        f"/v1/cluster-blueprints/{blueprint['id']}/artifact-dependencies",
        headers=ADMIN,
        json={"artifact_dependencies": ["art_0123456789abcdef"]},
    )
    assert missing.status_code == 404

    updated = client.put(
        f"/v1/cluster-blueprints/{blueprint['id']}/artifact-dependencies",
        headers=ADMIN,
        json={"artifact_dependencies": [artifact["id"]]},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["artifact_dependencies"] == [artifact["id"]]
