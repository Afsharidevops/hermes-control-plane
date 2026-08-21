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
BOT = {"Authorization": "Bearer test-bot"}
APPROVAL = {"Authorization": "Bearer test-approval"}
CREDENTIAL_SERVICE = {"Authorization": "Bearer test-credential-service"}
FP = "SHA256:" + "D" * 43


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(app) as c:
        yield c


def _credential(client: TestClient, credential_id: str = "cred_dev4infra123") -> dict:
    response = client.post(
        "/v1/internal/credential-refs/sync",
        headers=CREDENTIAL_SERVICE,
        json={
            "id": credential_id,
            "name": credential_id,
            "kind": "generic",
            "provider": "credential-service",
            "status": "configured",
            "metadata": {"fingerprint": "sha256:metadata-only", "scope": "provider-worker"},
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _provider(client: TestClient, kind: str = "aws", name: str = "primary-provider") -> dict:
    credential = _credential(client)
    response = client.post(
        "/v1/infrastructure-providers",
        headers=ADMIN,
        json={
            "name": name,
            "kind": kind,
            "endpoint": "https://provider.example.test",
            "credential_ref": credential["id"],
            "api_version": "2026-08-01",
            "implementation_version": "provider-worker-0.5.11-dev.4",
            "site": "dc1",
            "zone": "zone-a",
            "capabilities": {"dry_run": True},
            "labels": {"environment": "production"},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _approve(client: TestClient, changeset: dict) -> None:
    requested = client.post(f"/v1/changesets/{changeset['id']}/request-approval", headers=BOT)
    assert requested.status_code == 200, requested.text
    approved = client.post(
        f"/v1/changesets/{changeset['id']}/approve",
        headers=APPROVAL,
        json={"approver": "approval-bot:dev4", "plan_hash": changeset["plan_hash"]},
    )
    assert approved.status_code == 201, approved.text


def _ready_cluster(client: TestClient) -> dict:
    env = client.post("/v1/environments", headers=ADMIN, json={"name": "Fleet Prod", "risk_level": "HIGH"}).json()
    credential = client.post(
        "/v1/internal/credential-refs/sync",
        headers=CREDENTIAL_SERVICE,
        json={
            "id": "cred_dev4ssh12345",
            "name": "dev4-ssh",
            "kind": "ssh-key",
            "provider": "credential-service",
            "status": "configured",
            "metadata": {"fingerprint": "sha256:ssh-meta"},
        },
    ).json()
    server = client.post(
        "/v1/servers",
        headers=ADMIN,
        json={
            "hostname": "fleet-node-1",
            "environment_id": env["id"],
            "management_ip": "10.40.0.10",
            "ssh_port": 22,
            "ssh_user": "ubuntu",
            "host_fingerprint": FP,
            "connection_mode": "agent",
            "credential_ref": credential["id"],
            "site": "dc1",
            "zone": "zone-a",
            "labels": {"role": "worker"},
        },
    ).json()
    preflight = client.post(
        f"/v1/servers/{server['id']}/preflight-plan",
        headers=ADMIN,
        json={"requested_by": "hermes-bot:dev4", "source_channel": "hermes-bot"},
    )
    assert preflight.status_code == 201, preflight.text
    recorded = client.post(
        f"/v1/servers/{server['id']}/preflight-result",
        headers=ADMIN,
        json={
            "provider_job_id": preflight.json()["provider_job_id"],
            "status": "PASS",
            "summary": "ready for fleet test",
            "checks": [{"id": "ssh-connectivity", "status": "PASS"}],
            "facts": {"os": "ubuntu", "cpu_count": 4},
        },
    )
    assert recorded.status_code == 200, recorded.text
    blueprint = client.post(
        "/v1/cluster-blueprints",
        headers=ADMIN,
        json={
            "name": "dev4-fleet-blueprint",
            "provider": "k3s",
            "provider_version": "v1.35.6+k3s1",
            "kubernetes_version": "1.35.6",
            "network_plugin": "cilium",
            "hubble_enabled": True,
            "radar_enabled": True,
            "addon_defaults": [],
            "addon_versions": {
                "cilium": "1.18.1",
                "hubble": "1.18.1",
                "radar": "pinned-radar",
                "hermes-agent": "0.5.11-dev.4",
            },
            "labels": {"template": "fleet"},
        },
    ).json()
    profile = client.post(
        "/v1/cluster-profiles",
        headers=ADMIN,
        json={"name": "dev4-fleet-profile", "environment_id": env["id"], "blueprint_id": blueprint["id"], "server_ids": [server["id"]]},
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
        json={"name": "fleet-cluster-a", "environment_id": env["id"], "profile_id": profile["id"], "labels": {"team": "platform", "tier": "prod"}},
    ).json()
    with db.connect() as conn:
        conn.execute("UPDATE clusters SET state='READY' WHERE id=?", (cluster["id"],))
        conn.commit()
    return client.get(f"/v1/clusters/{cluster['id']}", headers=ADMIN).json()


def test_operations_center_contract_covers_compressed_dev4_scope(client: TestClient):
    contract = client.get("/v1/operations-center/contracts").json()
    assert contract["shared_intent_backend"] is True
    assert set(contract["channels"]) == {"ui", "telegram", "hermes-bot", "api"}
    assert set(contract["cloud_virtualization"]) == {"vmware", "vmware-workstation", "proxmox", "openstack", "aws", "azure", "gcp"}
    assert {"redfish", "ipmi", "pxe"}.issubset(contract["bare_metal"])
    assert contract["network"]["network-switch"]["arbitrary_cli"] is False
    assert set(contract["artifact_kinds"]) == {"oci-image", "helm-chart", "package", "git-release", "ansible-collection", "apt-repository", "rpm-repository", "python-repository"}
    assert "cluster.worker.replace" in contract["day2_operations"]
    assert "cluster.disaster-recovery" in contract["day2_operations"]
    assert "baseline-security" in contract["verification_checks"]
    assert "exact-hash binding" in contract["mutation_invariant"]


def test_shared_intent_backend_allows_read_ui_and_governed_mutation_channels(client: TestClient):
    read_plan = client.post(
        "/v1/operations-center/intents/plan",
        headers=ADMIN,
        json={
            "requested_by": "ui:operator",
            "source_channel": "ui",
            "domain": "read",
            "operation": "inventory.list",
            "selector": {"labels": {"team": "platform"}},
            "parameters": {"resource": "clusters"},
        },
    )
    assert read_plan.status_code == 201, read_plan.text
    assert read_plan.json()["changeset"] is None
    assert read_plan.json()["query_plan"]["mode"] == "read"

    provider = _provider(client)
    mutation = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={
            "requested_by": "telegram:42",
            "source_channel": "telegram",
            "domain": "cloud",
            "operation": "vm.create",
            "provider_id": provider["id"],
            "desired_state": {"name": "worker-42", "image": "ubuntu-24.04", "instance_type": "small"},
        },
    )
    assert mutation.status_code == 201, mutation.text
    body = mutation.json()
    assert body["mode"] == "mutation"
    assert body["changeset"]["state"] == "PREVIEWED"
    assert body["changeset"]["approval_required"] is True
    assert body["operation_job"]["state"] == "WAITING_APPROVAL"
    plan = body["operation_plan"]["plan"]
    assert plan["kind"] == "AWSResourcePlan"
    assert plan["credential_material_in_plan"] is False
    assert plan["provider"]["credential_ref"] == provider["credential_ref"]
    assert "password" not in str(plan).lower()


def test_operation_job_rejects_target_drift_after_exact_hash_approval(client: TestClient):
    provider = _provider(client)
    planned = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={
            "requested_by": "hermes-bot:cloud",
            "source_channel": "hermes-bot",
            "domain": "cloud",
            "operation": "vm.create",
            "provider_id": provider["id"],
            "desired_state": {"name": "drift-test", "image": "ubuntu-24.04", "instance_type": "small"},
        },
    ).json()
    _approve(client, planned["changeset"])

    health = client.post(
        f"/v1/infrastructure-providers/{provider['id']}/health",
        headers=ADMIN,
        json={"status": "HEALTHY", "detail": "probe changed provider snapshot", "observed_at": 1787160000, "evidence": {"latency_ms": 7}},
    )
    assert health.status_code == 200, health.text
    denied = client.post(f"/v1/operation-jobs/{planned['operation_job']['id']}/authorize", headers=BOT)
    assert denied.status_code == 409
    assert "target drift detected" in denied.text

    replanned = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={
            "requested_by": "hermes-bot:cloud",
            "source_channel": "hermes-bot",
            "domain": "cloud",
            "operation": "vm.create",
            "provider_id": provider["id"],
            "desired_state": {"name": "drift-test", "image": "ubuntu-24.04", "instance_type": "small"},
        },
    ).json()
    _approve(client, replanned["changeset"])
    authorized = client.post(f"/v1/operation-jobs/{replanned['operation_job']['id']}/authorize", headers=BOT)
    assert authorized.status_code == 200, authorized.text
    assert authorized.json()["state"] == "READY"


def test_raw_secret_material_and_embedded_credentials_are_rejected(client: TestClient):
    credential = _credential(client)
    bad_provider = client.post(
        "/v1/infrastructure-providers",
        headers=ADMIN,
        json={
            "name": "bad-provider",
            "kind": "vmware",
            "endpoint": "https://admin:supersecret@vcenter.example.test/sdk",
            "credential_ref": credential["id"],
            "api_version": "9.0",
            "implementation_version": "worker-1",
        },
    )
    assert bad_provider.status_code == 422
    assert "Credential Service reference" in bad_provider.text

    provider = _provider(client, kind="azure", name="azure-safe")
    leaked_plan = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={
            "requested_by": "hermes-bot:test",
            "source_channel": "hermes-bot",
            "domain": "cloud",
            "operation": "vm.create",
            "provider_id": provider["id"],
            "desired_state": {"name": "bad", "client_secret": "should-never-enter-plan"},
        },
    )
    assert leaked_plan.status_code == 422
    assert "raw secret material is forbidden" in leaked_plan.text


def test_airgap_artifact_plan_requires_digest_and_is_changeset_governed(client: TestClient):
    missing_digest = client.post(
        "/v1/artifact-mirror/items",
        headers=ADMIN,
        json={"name": "cilium", "kind": "helm-chart", "source": "oci://registry.example/cilium", "destination": "oci://mirror.local/cilium", "version": "1.18.1", "digest": "latest"},
    )
    assert missing_digest.status_code == 422

    digest = "sha256:" + "a" * 64
    item = client.post(
        "/v1/artifact-mirror/items",
        headers=ADMIN,
        json={"name": "cilium", "kind": "helm-chart", "source": "oci://registry.example/cilium", "destination": "oci://mirror.local/cilium", "version": "1.18.1", "digest": digest},
    )
    assert item.status_code == 201, item.text
    planned = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={
            "requested_by": "hermes-bot:airgap",
            "source_channel": "hermes-bot",
            "domain": "artifact",
            "operation": "artifact.mirror.apply",
            "target_id": item.json()["id"],
            "parameters": {"verify_destination": True},
        },
    )
    assert planned.status_code == 201, planned.text
    plan = planned.json()["operation_plan"]["plan"]
    assert plan["digest_verification_required"] is True
    assert plan["artifact"]["digest"] == digest
    assert plan["stages"][2] == "verify-source-digest"
    assert planned.json()["changeset"]["approval_required"] is True


def test_fleet_selector_is_bound_to_exact_cluster_snapshots(client: TestClient):
    cluster = _ready_cluster(client)
    planned = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={
            "requested_by": "hermes-bot:fleet",
            "source_channel": "hermes-bot",
            "domain": "fleet",
            "operation": "cluster.node.cordon",
            "selector": {"labels": {"team": "platform"}, "sites": ["dc1"]},
            "parameters": {"node": "fleet-node-1"},
        },
    )
    assert planned.status_code == 201, planned.text
    body = planned.json()
    plan = body["operation_plan"]["plan"]
    assert plan["exact_target_count"] == 1
    assert plan["targets"][0]["id"] == cluster["id"]
    assert plan["target_drift_policy"] == "reject-on-snapshot-change"
    _approve(client, body["changeset"])

    with db.connect() as conn:
        conn.execute("UPDATE clusters SET kubernetes_version='1.35.7' WHERE id=?", (cluster["id"],))
        conn.commit()
    denied = client.post(f"/v1/operation-jobs/{body['operation_job']['id']}/authorize", headers=BOT)
    assert denied.status_code == 409
    assert cluster["id"] in denied.text


def test_unified_verification_is_typed_and_secret_safe(client: TestClient):
    provider = _provider(client)
    bad = client.post(
        "/v1/verifications",
        headers=BOT,
        json={
            "subject_type": "provider",
            "subject_id": provider["id"],
            "actor": "provider-worker:test",
            "observed_at": 1787161000,
            "checks": [{"id": "connectivity", "status": "PASS", "summary": "reachable", "evidence": {"api_key": "leak"}}],
        },
    )
    assert bad.status_code == 422

    good = client.post(
        "/v1/verifications",
        headers=BOT,
        json={
            "subject_type": "provider",
            "subject_id": provider["id"],
            "actor": "provider-worker:test",
            "observed_at": 1787161001,
            "checks": [
                {"id": "connectivity", "status": "PASS", "summary": "provider endpoint reachable", "evidence": {"latency_ms": 8}},
                {"id": "baseline-security", "status": "WARN", "summary": "manual policy review pending", "evidence": {}},
            ],
            "evidence": {"contract": "typed-verification-v4"},
        },
    )
    assert good.status_code == 201, good.text
    assert good.json()["status"] == "WARN"
    listed = client.get(f"/v1/verifications?subject_id={provider['id']}", headers=ADMIN)
    assert listed.status_code == 200
    assert listed.json()[0]["checks"][0]["id"] == "connectivity"


def test_operation_job_uses_signed_ticket_consumes_approval_and_records_changeset_execution(client: TestClient):
    provider = _provider(client)
    planned = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={
            "requested_by": "hermes-bot:ticket-test",
            "source_channel": "hermes-bot",
            "domain": "cloud",
            "operation": "vm.create",
            "provider_id": provider["id"],
            "desired_state": {"name": "ticket-vm", "image": "ubuntu-24.04", "instance_type": "small"},
        },
    ).json()
    _approve(client, planned["changeset"])
    authorized = client.post(f"/v1/operation-jobs/{planned['operation_job']['id']}/authorize", headers=BOT)
    assert authorized.status_code == 200, authorized.text
    auth = authorized.json()
    assert auth["state"] == "READY"
    assert auth["execution_ticket"]["changeset_id"] == planned["changeset"]["id"]
    assert auth["execution_ticket"]["preconditions"]["operation_job_id"] == planned["operation_job"]["id"]
    assert len(auth["signature"]) == 64
    assert "signature" not in str(auth["request"])

    tampered = dict(auth["execution_ticket"])
    tampered["preconditions"] = dict(tampered["preconditions"])
    tampered["preconditions"]["executor"] = "untrusted-worker"
    denied = client.post(
        f"/v1/operation-jobs/{planned['operation_job']['id']}/transition",
        headers=BOT,
        json={
            "state": "RUNNING",
            "stage": "apply",
            "message": "tampered ticket must fail",
            "execution_ticket": tampered,
            "signature": auth["signature"],
            "evidence": {},
        },
    )
    assert denied.status_code == 409
    assert "ticket" in denied.text.lower()

    running = client.post(
        f"/v1/operation-jobs/{planned['operation_job']['id']}/transition",
        headers=BOT,
        json={
            "state": "RUNNING",
            "stage": "apply",
            "message": "provider worker accepted constrained plan",
            "execution_ticket": auth["execution_ticket"],
            "signature": auth["signature"],
            "evidence": {"provider_job_ref": "worker-job-1"},
        },
    )
    assert running.status_code == 200, running.text
    assert running.json()["state"] == "RUNNING"
    changeset = client.get(f"/v1/changesets/{planned['changeset']['id']}").json()
    assert changeset["state"] == "EXECUTING"
    with db.connect() as conn:
        approval = conn.execute("SELECT status,consumed_at FROM approvals WHERE changeset_id=?", (planned["changeset"]["id"],)).fetchone()
        assert approval["status"] == "CONSUMED"
        assert approval["consumed_at"] is not None

    completed = client.post(
        f"/v1/operation-jobs/{planned['operation_job']['id']}/transition",
        headers=BOT,
        json={
            "state": "SUCCEEDED",
            "stage": "verify",
            "message": "provider worker completed typed operation",
            "execution_ticket": auth["execution_ticket"],
            "signature": auth["signature"],
            "evidence": {"resource_id": "vm-123"},
        },
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["state"] == "SUCCEEDED"
    changeset = client.get(f"/v1/changesets/{planned['changeset']['id']}").json()
    assert changeset["state"] == "EXECUTED"


def test_operation_job_rejects_tampered_persisted_typed_plan_and_invalid_approval_mac(client: TestClient):
    provider = _provider(client)
    planned = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={
            "requested_by": "hermes-bot:binding-test",
            "source_channel": "hermes-bot",
            "domain": "cloud",
            "operation": "vm.create",
            "provider_id": provider["id"],
            "desired_state": {"name": "bound-vm", "image": "ubuntu-24.04", "instance_type": "small"},
        },
    ).json()
    _approve(client, planned["changeset"])
    with db.connect() as conn:
        row = conn.execute("SELECT plan_json FROM operation_plans WHERE id=?", (planned["operation_plan"]["id"],)).fetchone()
        import json
        typed = json.loads(row["plan_json"])
        typed["desired_state"]["instance_type"] = "xlarge"
        conn.execute("UPDATE operation_plans SET plan_json=? WHERE id=?", (json.dumps(typed, sort_keys=True), planned["operation_plan"]["id"]))
        conn.commit()
    denied = client.post(f"/v1/operation-jobs/{planned['operation_job']['id']}/authorize", headers=BOT)
    assert denied.status_code == 409
    assert "typed plan hash" in denied.text.lower() or "exactly bound" in denied.text.lower()

    replanned = client.post(
        "/v1/operations-center/intents/plan",
        headers=BOT,
        json={
            "requested_by": "hermes-bot:binding-test",
            "source_channel": "hermes-bot",
            "domain": "cloud",
            "operation": "vm.create",
            "provider_id": provider["id"],
            "desired_state": {"name": "bound-vm-2", "image": "ubuntu-24.04", "instance_type": "small"},
        },
    ).json()
    _approve(client, replanned["changeset"])
    with db.connect() as conn:
        conn.execute("UPDATE approvals SET mac='00' WHERE changeset_id=?", (replanned["changeset"]["id"],))
        conn.commit()
    invalid_approval = client.post(f"/v1/operation-jobs/{replanned['operation_job']['id']}/authorize", headers=BOT)
    assert invalid_approval.status_code == 409
    assert "integrity-checked approval" in invalid_approval.text
