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
FP = "SHA256:" + "A" * 43


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(app) as c:
        yield c


def _environment(client: TestClient) -> dict:
    response = client.post("/v1/environments", headers=ADMIN, json={"name": "Prod", "risk_level": "HIGH"})
    assert response.status_code == 201, response.text
    return response.json()


def _ssh_credential(client: TestClient) -> dict:
    payload = {
        "id": "cred_ssh12345678",
        "name": "prod-ssh",
        "kind": "ssh-key",
        "provider": "local-encrypted",
        "status": "configured",
        "metadata": {"backend": "local-encrypted", "fingerprint": "sha256:" + "a" * 64, "version": 1},
    }
    response = client.post("/v1/internal/credential-refs/sync", headers=CREDENTIAL_SERVICE, json=payload)
    assert response.status_code == 200, response.text
    return response.json()


def _server(client: TestClient) -> dict:
    env = _environment(client)
    cred = _ssh_credential(client)
    response = client.post(
        "/v1/servers",
        headers=ADMIN,
        json={
            "hostname": "node01.example.internal",
            "environment_id": env["id"],
            "management_ip": "10.20.0.11",
            "provisioning_ip": "10.30.0.11",
            "ssh_port": 22,
            "ssh_user": "platform",
            "host_fingerprint": FP,
            "connection_mode": "agent",
            "credential_ref": cred["id"],
            "site": "dc1",
            "rack": "r01",
            "labels": {"role": "cluster-node"},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_server_registry_enforces_ssh_binding_fingerprint_and_duplicate_ips(client: TestClient):
    first = _server(client)
    assert first["credential_ref"] == "cred_ssh12345678"
    assert first["host_fingerprint"] == FP
    assert first["preflight_status"] == "UNKNOWN"

    env = client.get("/v1/environments").json()[0]
    duplicate = client.post(
        "/v1/servers",
        headers=ADMIN,
        json={
            "hostname": "node02.example.internal",
            "environment_id": env["id"],
            "management_ip": first["provisioning_ip"],
            "host_fingerprint": FP,
            "credential_ref": first["credential_ref"],
        },
    )
    assert duplicate.status_code == 409

    bad_fp = client.patch(f"/v1/servers/{first['id']}", headers=ADMIN, json={"host_fingerprint": "ssh-rsa-not-a-fingerprint"})
    assert bad_fp.status_code == 422


def test_preflight_is_fixed_read_only_changeset_and_can_issue_agent_task(client: TestClient):
    server = _server(client)
    spec = client.get("/v1/preflight/ssh/spec").json()
    assert spec["host_key_policy"] == "pinned-fingerprint-required"
    assert len(spec["checks"]) >= 10
    assert all(check["command"] for check in spec["checks"])

    planned = client.post(f"/v1/servers/{server['id']}/preflight-plan", headers=ADMIN)
    assert planned.status_code == 201, planned.text
    planned_body = planned.json()
    changeset = planned_body["changeset"]
    assert planned_body["execution"] == "agent-task"
    events = client.get(f"/v1/provider-jobs/{planned_body['provider_job_id']}/events", headers=ADMIN)
    assert events.status_code == 200
    assert events.json()[0]["status"] == "READY"
    assert changeset["risk"] == "READ"
    assert changeset["state"] == "PREVIEWED"
    assert changeset["approval_required"] is False
    assert changeset["plan"]["target_snapshot"]["host_fingerprint"] == FP

    token = client.post("/v1/agents/enrollment-tokens", headers=ADMIN, json={"name": "preflight-agent"}).json()["enrollment_token"]
    agent = client.post("/v1/agents/enroll", json={"enrollment_token": token, "capabilities": ["ssh.preflight", "bootstrap.apply"]}).json()
    task = client.post(
        f"/v1/agents/{agent['id']}/tasks",
        headers=ADMIN,
        json={"changeset_id": changeset["id"], "capability": "ssh.preflight"},
    )
    assert task.status_code == 201, task.text
    assert task.json()["envelope"]["changeset_hash"] == changeset["plan_hash"]


def test_bootstrap_requires_passed_preflight_and_exact_changeset_approval(client: TestClient):
    server = _server(client)
    payload = {
        "provider": "kubespray",
        "requested_by": "telegram:operator",
        "source_channel": "telegram",
        "cluster_name": "prod-a",
        "kubernetes_version": "1.35.6",
        "node_role": "control-plane-worker",
        "network_plugin": "cilium",
        "hubble_enabled": True,
        "radar_enabled": True,
    }
    blocked = client.post(f"/v1/servers/{server['id']}/bootstrap-plan", headers=BOT, json=payload)
    assert blocked.status_code == 409

    preflight = client.post(f"/v1/servers/{server['id']}/preflight-plan", headers=ADMIN)
    assert preflight.status_code == 201, preflight.text
    recorded = client.post(
        f"/v1/servers/{server['id']}/preflight-result",
        headers=ADMIN,
        json={
            "provider_job_id": preflight.json()["provider_job_id"],
            "status": "PASS",
            "summary": "all required checks passed",
            "checks": [{"id": "ssh-connectivity", "status": "PASS"}],
            "facts": {"os": "ubuntu", "cpu_count": 8, "memory_bytes": 17179869184},
        },
    )
    assert recorded.status_code == 200, recorded.text

    planned = client.post(f"/v1/servers/{server['id']}/bootstrap-plan", headers=BOT, json=payload)
    assert planned.status_code == 201, planned.text
    body = planned.json()
    changeset = body["changeset"]
    assert changeset["risk"] == "HIGH"
    assert changeset["approval_required"] is True
    assert changeset["state"] == "PREVIEWED"
    assert body["provider"]["mutation_policy"] == "changeset-only"
    assert changeset["parameters"]["radar_enabled"] is True
    assert changeset["parameters"]["hubble_enabled"] is True

    too_early = client.post(f"/v1/provider-jobs/{body['provider_job_id']}/authorize", headers=BOT)
    assert too_early.status_code == 409
    assert client.post(f"/v1/changesets/{changeset['id']}/request-approval", headers=BOT).status_code == 200
    approved = client.post(
        f"/v1/changesets/{changeset['id']}/approve",
        headers=APPROVAL,
        json={"approver": "approval-bot:separate", "plan_hash": changeset["plan_hash"]},
    )
    assert approved.status_code == 201, approved.text
    authorized = client.post(f"/v1/provider-jobs/{body['provider_job_id']}/authorize", headers=BOT)
    assert authorized.status_code == 200, authorized.text
    assert authorized.json()["state"] == "READY"

    running = client.post(
        f"/v1/provider-jobs/{body['provider_job_id']}/transition",
        headers=BOT,
        json={"state": "RUNNING", "stage": "apply", "message": "bootstrap worker started", "evidence": {"stage_index": 1}},
    )
    assert running.status_code == 200, running.text
    paused = client.post(
        f"/v1/provider-jobs/{body['provider_job_id']}/transition",
        headers=BOT,
        json={"state": "PAUSED", "stage": "apply", "message": "waiting for worker recovery", "evidence": {}},
    )
    assert paused.status_code == 200, paused.text
    resumed = client.post(
        f"/v1/provider-jobs/{body['provider_job_id']}/resume", headers=BOT, json={"reason": "worker recovered"}
    )
    assert resumed.status_code == 200, resumed.text
    assert resumed.json()["state"] == "READY"
    assert resumed.json()["attempt"] == 1
    failed = client.post(
        f"/v1/provider-jobs/{body['provider_job_id']}/transition",
        headers=BOT,
        json={"state": "FAILED", "stage": "apply", "message": "transient provider failure", "evidence": {"retryable": True}},
    )
    assert failed.status_code == 200, failed.text
    retried = client.post(
        f"/v1/provider-jobs/{body['provider_job_id']}/retry", headers=BOT, json={"reason": "retry transient failure"}
    )
    assert retried.status_code == 200, retried.text
    assert retried.json()["attempt"] == 2
    assert retried.json()["state"] == "READY"
    assert client.post(
        f"/v1/provider-jobs/{body['provider_job_id']}/transition",
        headers=BOT,
        json={"state": "RUNNING", "stage": "verify", "message": "verification running", "evidence": {}},
    ).status_code == 200
    succeeded = client.post(
        f"/v1/provider-jobs/{body['provider_job_id']}/transition",
        headers=BOT,
        json={"state": "SUCCEEDED", "stage": "verify", "message": "bootstrap verified", "evidence": {"verified": True}},
    )
    assert succeeded.status_code == 200, succeeded.text
    events = client.get(f"/v1/provider-jobs/{body['provider_job_id']}/events", headers=ADMIN).json()
    assert [event["status"] for event in events][-2:] == ["RUNNING", "SUCCEEDED"]
    after = client.get(f"/v1/provider-jobs/{body['provider_job_id']}/events?after_id={events[-2]['id']}", headers=ADMIN).json()
    assert len(after) == 1 and after[0]["status"] == "SUCCEEDED"


def test_radar_and_hubble_are_first_class_but_never_governance_bypasses(client: TestClient):
    providers = {item["id"]: item for item in client.get("/v1/providers").json()}
    assert providers["radar"]["status"] == "first-class-provider-foundation"
    assert providers["radar"]["governance_bypass"] is False
    assert providers["hubble"]["governance_bypass"] is False
    assert providers["hubble"]["redaction"] == "required-before-ai-ui"
    capabilities = {item["id"]: item for item in client.get("/v1/capabilities").json()}
    assert capabilities["radar.apply"]["approval"] == "policy"
    assert "ChangeSet" in capabilities["radar.apply"]["target_restrictions"][0]


def test_direct_ssh_preflight_uses_provider_worker_foundation(client: TestClient):
    server = _server(client)
    updated = client.patch(f"/v1/servers/{server['id']}", headers=ADMIN, json={"connection_mode": "direct"})
    assert updated.status_code == 200, updated.text
    planned = client.post(f"/v1/servers/{server['id']}/preflight-plan", headers=ADMIN)
    assert planned.status_code == 201, planned.text
    assert planned.json()["execution"] == "ssh-provider-worker"
    assert planned.json()["changeset"]["risk"] == "READ"


def test_provider_job_event_stream_terminates_for_terminal_job(client: TestClient):
    server = _server(client)
    planned = client.post(f"/v1/servers/{server['id']}/preflight-plan", headers=ADMIN).json()
    result = client.post(
        f"/v1/servers/{server['id']}/preflight-result",
        headers=ADMIN,
        json={
            "provider_job_id": planned["provider_job_id"],
            "status": "FAIL",
            "summary": "host did not meet required checks",
            "checks": [{"id": "authority", "status": "FAIL"}],
            "facts": {"hostname": "node01.example.internal"},
        },
    )
    assert result.status_code == 200, result.text
    with client.stream("GET", f"/v1/provider-jobs/{planned['provider_job_id']}/stream", headers=ADMIN) as response:
        assert response.status_code == 200
        text = "\n".join(response.iter_lines())
    assert "event: provider-job" in text
    assert "event: end" in text
    assert '"state": "FAILED"' in text
