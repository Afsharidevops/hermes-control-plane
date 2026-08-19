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
BOT = {"Authorization": "Bearer test-bot"}
APPROVAL = {"Authorization": "Bearer test-approval"}
CREDENTIAL_SERVICE = {"Authorization": "Bearer test-credential-service"}
FP = "SHA256:" + "B" * 43


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(app) as c:
        yield c


def _ready_server(client: TestClient) -> tuple[dict, dict]:
    env = client.post("/v1/environments", headers=ADMIN, json={"name": "Prod", "risk_level": "HIGH"}).json()
    cred = client.post(
        "/v1/internal/credential-refs/sync",
        headers=CREDENTIAL_SERVICE,
        json={
            "id": "cred_dev3ssh12345",
            "name": "dev3-ssh",
            "kind": "ssh-key",
            "provider": "local-encrypted",
            "status": "configured",
            "metadata": {"backend": "local-encrypted", "fingerprint": "sha256:" + "c" * 64, "version": 1},
        },
    ).json()
    server_response = client.post(
        "/v1/servers",
        headers=ADMIN,
        json={
            "hostname": "cp01.example.internal",
            "environment_id": env["id"],
            "management_ip": "10.60.0.11",
            "host_fingerprint": FP,
            "connection_mode": "agent",
            "credential_ref": cred["id"],
        },
    )
    assert server_response.status_code == 201, server_response.text
    server = server_response.json()
    preflight = client.post(f"/v1/servers/{server['id']}/preflight-plan", headers=ADMIN)
    assert preflight.status_code == 201, preflight.text
    recorded = client.post(
        f"/v1/servers/{server['id']}/preflight-result",
        headers=ADMIN,
        json={
            "provider_job_id": preflight.json()["provider_job_id"],
            "status": "PASS",
            "summary": "dev3 cluster node passed fixed SSH preflight",
            "checks": [{"id": "ssh-connectivity", "status": "PASS"}],
            "facts": {"os": "ubuntu", "cpu_count": 8, "memory_bytes": 17179869184},
        },
    )
    assert recorded.status_code == 200, recorded.text
    return env, recorded.json()


def _cluster(client: TestClient, provider: str = "kubespray") -> dict:
    env, server = _ready_server(client)
    blueprint = client.post(
        "/v1/cluster-blueprints",
        headers=ADMIN,
        json={
            "name": f"{provider}-blueprint",
            "provider": provider,
            "provider_version": "pinned-provider-test",
            "kubernetes_version": "1.35.6",
            "network_plugin": "cilium",
            "hubble_enabled": True,
            "radar_enabled": True,
            "addon_defaults": ["cert-manager", "kube-prometheus-stack"],
            "addon_versions": {
                "cilium": "pinned-test",
                "hubble": "pinned-test",
                "radar": "pinned-test",
                "hermes-agent": "pinned-test",
                "cert-manager": "pinned-test",
                "kube-prometheus-stack": "pinned-test",
            },
            "topology": {"control_plane_replicas": 1},
        },
    )
    assert blueprint.status_code == 201, blueprint.text
    profile = client.post(
        "/v1/cluster-profiles",
        headers=ADMIN,
        json={"name": f"{provider}-profile", "environment_id": env["id"], "blueprint_id": blueprint.json()["id"], "server_ids": [server["id"]]},
    )
    assert profile.status_code == 201, profile.text
    role = client.post(
        "/v1/node-roles",
        headers=ADMIN,
        json={"profile_id": profile.json()["id"], "role": "control-plane-worker", "server_ids": [server["id"]]},
    )
    assert role.status_code == 201, role.text
    cluster = client.post(
        "/v1/clusters",
        headers=ADMIN,
        json={"name": f"{provider}-cluster", "environment_id": env["id"], "profile_id": profile.json()["id"]},
    )
    assert cluster.status_code == 201, cluster.text
    return cluster.json()


def test_cluster_factory_contract_exposes_all_dev3_resource_types(client: TestClient):
    contract = client.get("/v1/cluster-factory/contracts").json()
    assert contract["resource_types"] == ["ClusterBlueprint", "ClusterProfile", "Cluster", "NodeRole", "ProvisioningRun", "AddonPlan", "UpgradePlan", "BackupPlan"]
    assert set(contract["providers"]) == {"kubespray", "k3s", "rke2"}
    assert contract["radar"]["governance_bypass"] is False
    assert contract["hubble"]["redaction"] == "required-before-ai-ui"
    assert set(contract["operational_profiles"]) == {"lab-minimal", "lab-full", "production", "production-ha", "production-hardened"}
    assert {"kube-vip", "metallb", "velero"}.issubset(contract["operational_profiles"]["production"]["addons"])
    assert contract["aban_runtime_dependency"] is False

    catalog = client.get("/v1/cluster-factory/operational-profiles")
    assert catalog.status_code == 200
    lab_addons = catalog.json()["lab-minimal"]["addons"]
    preset = client.post(
        "/v1/cluster-blueprints/from-operational-profile",
        headers=ADMIN,
        json={
            "name": "preset-lab-minimal",
            "operational_profile": "lab-minimal",
            "kubernetes_version": "1.35.6",
            "provider_version": "pinned-provider-test",
            "addon_versions": {name: "pinned-test" for name in lab_addons},
        },
    )
    assert preset.status_code == 201, preset.text
    assert preset.json()["provider"] == "k3s"
    assert preset.json()["labels"]["operational_profile"] == "lab-minimal"


@pytest.mark.parametrize(
    ("provider", "payload_kind"),
    [("kubespray", "KubesprayExecutionSpec"), ("k3s", "K3sExecutionSpec"), ("rke2", "RKE2ExecutionSpec")],
)
def test_each_cluster_provider_gets_a_deterministic_typed_execution_spec(client: TestClient, provider: str, payload_kind: str):
    cluster = _cluster(client, provider)
    run = client.post(
        f"/v1/clusters/{cluster['id']}/provisioning-runs",
        headers=BOT,
        json={"requested_by": "hermes-bot:test", "source_channel": "hermes-bot"},
    )
    assert run.status_code == 201, run.text
    body = run.json()
    assert body["provider"] == provider
    assert body["plan"]["provider_payload"]["kind"] == payload_kind
    assert body["plan"]["provider_version"] == "pinned-provider-test"
    assert all(item["version"] == "pinned-test" for item in body["plan"]["addons"])
    assert body["plan"]["network_plugin"] == "cilium"
    assert body["changeset"]["risk"] == "HIGH"
    assert body["changeset"]["state"] == "PREVIEWED"
    assert body["changeset"]["approval_required"] is True
    job = client.get(f"/v1/provider-jobs/{body['provider_job_ids'][0]}", headers=ADMIN).json()
    assert job["plan_hash"] == body["changeset"]["plan_hash"]
    assert job["state"] == "WAITING_APPROVAL"


def test_cluster_provisioning_addons_upgrade_backup_and_intelligence_are_governed(client: TestClient):
    cluster = _cluster(client, "kubespray")
    run_response = client.post(
        f"/v1/clusters/{cluster['id']}/provisioning-runs",
        headers=BOT,
        json={"requested_by": "telegram:operator", "source_channel": "telegram"},
    )
    assert run_response.status_code == 201, run_response.text
    run = run_response.json()
    changeset = run["changeset"]
    assert client.post(f"/v1/changesets/{changeset['id']}/request-approval", headers=BOT).status_code == 200
    approved = client.post(
        f"/v1/changesets/{changeset['id']}/approve",
        headers=APPROVAL,
        json={"approver": "approval-bot:separate", "plan_hash": changeset["plan_hash"]},
    )
    assert approved.status_code == 201, approved.text
    job_id = run["provider_job_ids"][0]
    assert client.post(f"/v1/provider-jobs/{job_id}/authorize", headers=BOT).status_code == 200
    assert client.post(f"/v1/provider-jobs/{job_id}/transition", headers=BOT, json={"state": "RUNNING", "stage": "apply", "message": "provider worker started", "evidence": {}}).status_code == 200
    assert client.post(f"/v1/provider-jobs/{job_id}/transition", headers=BOT, json={"state": "SUCCEEDED", "stage": "verify", "message": "cluster verified", "evidence": {"verified": True}}).status_code == 200
    refreshed = client.post(f"/v1/provisioning-runs/{run['id']}/refresh", headers=ADMIN)
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["state"] == "SUCCEEDED"
    assert client.get(f"/v1/clusters/{cluster['id']}", headers=ADMIN).json()["state"] == "READY"

    missing_pin = client.post(
        f"/v1/clusters/{cluster['id']}/addon-plans",
        headers=BOT,
        json={"requested_by": "hermes-bot:test", "source_channel": "hermes-bot", "addons": ["longhorn"], "versions": {}},
    )
    assert missing_pin.status_code == 422
    addon = client.post(
        f"/v1/clusters/{cluster['id']}/addon-plans",
        headers=BOT,
        json={"requested_by": "hermes-bot:test", "source_channel": "hermes-bot", "addons": ["longhorn", "cert-manager", "argocd", "opencost", "velero"], "versions": {"longhorn": "pinned-test", "cert-manager": "pinned-test", "argocd": "pinned-test", "opencost": "pinned-test", "velero": "pinned-test"}},
    )
    assert addon.status_code == 201, addon.text
    assert addon.json()["changeset"]["approval_required"] is True
    assert addon.json()["plan"]["addons"][0]["version_pin_required"] is True

    upgrade = client.post(
        f"/v1/clusters/{cluster['id']}/upgrade-plans",
        headers=BOT,
        json={"requested_by": "hermes-bot:test", "source_channel": "hermes-bot", "target_version": "1.36.1"},
    )
    assert upgrade.status_code == 201, upgrade.text
    assert upgrade.json()["plan"]["stages"][1] == "backup"
    assert upgrade.json()["changeset"]["risk"] == "HIGH"

    backup = client.post(
        f"/v1/clusters/{cluster['id']}/backup-plans",
        headers=BOT,
        json={"requested_by": "hermes-bot:test", "source_channel": "hermes-bot", "provider": "velero", "schedule": "0 2 * * *", "retention_count": 14, "scope": {"namespaces": ["apps"]}},
    )
    assert backup.status_code == 201, backup.text
    assert backup.json()["plan"]["restore_verification"] is True

    radar = client.post(
        f"/v1/clusters/{cluster['id']}/intelligence/radar",
        headers=ADMIN,
        json={"observed_at": 1787120000, "health_score": 92, "resource_counts": {"pods": 42}, "degraded_workloads": ["apps/api"], "warning_event_counts": {"BackOff": 2}, "addon_health": {"cilium": "healthy"}},
    )
    assert radar.status_code == 201, radar.text
    assert radar.json()["contract"]["writes"] == "translate-to-hermes-changeset"

    hubble = client.post(
        f"/v1/clusters/{cluster['id']}/intelligence/hubble",
        headers=ADMIN,
        json={"window_start": 1787119900, "window_end": 1787120000, "verdict_counts": {"FORWARDED": 120, "DROPPED": 3}, "namespace_pairs": [{"source": "apps", "destination": "database", "count": 12}], "service_pairs": [], "policy_drop_counts": {"default-deny": 3}},
    )
    assert hubble.status_code == 201, hubble.text
    assert "raw-payloads" in hubble.json()["contract"]["forbidden_for_ai_ui"]

    intelligence = client.get(f"/v1/clusters/{cluster['id']}/intelligence", headers=ADMIN)
    assert intelligence.status_code == 200, intelligence.text
    body = intelligence.json()
    assert body["latest"]["radar"]["summary"]["health_score"] == 92
    assert body["latest"]["hubble"]["summary"]["verdict_counts"]["DROPPED"] == 3
    assert any(item["id"] == "network.policy-drops" for item in body["diagnostics"])
