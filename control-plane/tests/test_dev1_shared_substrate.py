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

from hermes_control_plane import db  # noqa: E402
from hermes_control_plane.main import app  # noqa: E402

AUTH = {"Authorization": "Bearer test-admin"}


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(app) as c:
        yield c


def _env(client: TestClient, name: str = "Dev") -> dict:
    response = client.post("/v1/environments", headers=AUTH, json={"name": name, "risk_level": "LOW"})
    assert response.status_code == 201, response.text
    return response.json()


def _agent_target(client: TestClient, env_id: str) -> dict:
    response = client.post(
        "/v1/targets",
        headers=AUTH,
        json={
            "name": "docker-edge",
            "kind": "docker",
            "environment_id": env_id,
            "connection_mode": "agent",
            "scope": {"container_allowlist": ["app-*"], "privileged": False},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _enroll_agent(client: TestClient, capabilities: list[str]) -> tuple[dict, dict[str, str]]:
    issued = client.post("/v1/agents/enrollment-tokens", headers=AUTH, json={"name": "edge-dev", "ttl_seconds": 300})
    assert issued.status_code == 201, issued.text
    enrolled = client.post(
        "/v1/agents/enroll",
        json={"enrollment_token": issued.json()["enrollment_token"], "capabilities": capabilities},
    )
    assert enrolled.status_code == 201, enrolled.text
    body = enrolled.json()
    return body, {"Authorization": f"Bearer {body['agent_token']}"}


def _previewed_docker_changeset(client: TestClient, target_id: str) -> dict:
    created = client.post(
        "/v1/changesets",
        headers=AUTH,
        json={
            "operation": "list.containers",
            "adapter": "docker",
            "target_id": target_id,
            "requested_by": "admin:test",
            "source_channel": "api",
            "parameters": {},
        },
    )
    assert created.status_code == 201, created.text
    changeset = created.json()
    assert changeset["risk"] == "READ"
    previewed = client.post(
        f"/v1/changesets/{changeset['id']}/preview",
        headers=AUTH,
        json={"summary": "List allowed Docker containers", "details": {"mutation": False}},
    )
    assert previewed.status_code == 200, previewed.text
    return previewed.json()


def test_application_registry_crud_is_audited(client: TestClient):
    env = _env(client)
    target = _agent_target(client, env["id"])

    created = client.post(
        "/v1/applications",
        headers=AUTH,
        json={
            "name": "payments",
            "environment_id": env["id"],
            "target_id": target["id"],
            "source_repository": "https://github.example/platform/payments.git",
            "revision_policy": "main",
            "build_context": ".",
            "image_repository": "registry.example/payments",
            "deployment_type": "compose",
            "values_files": ["compose.production.yaml"],
            "verification_checks": [{"kind": "http", "url": "https://payments.example/health"}],
            "rollback_strategy": {"kind": "previous-image-digest"},
            "labels": {"team": "payments"},
        },
    )
    assert created.status_code == 201, created.text
    app = created.json()
    assert app["deployment_type"] == "compose"
    assert app["rollback_strategy"]["kind"] == "previous-image-digest"

    updated = client.patch(
        f"/v1/applications/{app['id']}",
        headers=AUTH,
        json={"revision_policy": "release/*", "labels": {"team": "payments", "tier": "critical"}},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["revision_policy"] == "release/*"
    assert len(client.get("/v1/applications").json()) == 1

    events = client.get("/v1/audit").json()
    assert any(event["event_type"] == "application.created" and event["subject_id"] == app["id"] for event in events)
    assert any(event["event_type"] == "application.updated" and event["subject_id"] == app["id"] for event in events)

    deleted = client.delete(f"/v1/applications/{app['id']}", headers=AUTH)
    assert deleted.status_code == 204


def test_capability_contract_declares_security_properties(client: TestClient):
    response = client.get("/v1/capabilities")
    assert response.status_code == 200
    capabilities = {row["id"]: row for row in response.json()}
    for capability_id in ["kubernetes.apply", "docker.read", "swarm.deploy", "ssh.runbook.execute", "github.gitops", "gitlab.gitops"]:
        row = capabilities[capability_id]
        assert row["mode"] in {"read", "write"}
        assert row["default_risk"] in {"READ", "LOW", "HIGH", "CRITICAL"}
        assert row["credential_class"]
        assert row["connection_modes"]
        assert row["approval"] in {"none", "policy"}
        assert isinstance(row["target_restrictions"], list)
    assert "no unrestricted shell endpoint" in capabilities["ssh.runbook.execute"]["target_restrictions"]
    assert capabilities["docker.read"]["connection_modes"] == ["agent"]


def test_agent_signed_task_claim_result_and_replay_protection(client: TestClient):
    env = _env(client)
    target = _agent_target(client, env["id"])
    agent, agent_auth = _enroll_agent(client, ["docker.read"])
    changeset = _previewed_docker_changeset(client, target["id"])

    issued = client.post(
        f"/v1/agents/{agent['id']}/tasks",
        headers=AUTH,
        json={"changeset_id": changeset["id"], "capability": "docker.read", "ttl_seconds": 300},
    )
    assert issued.status_code == 201, issued.text
    task = issued.json()
    assert task["state"] == "ISSUED"
    assert task["signature"]
    assert task["envelope"]["changeset_hash"] == changeset["plan_hash"]
    assert task["envelope"]["policy_generation"] == changeset["policy_generation"]

    next_task = client.get("/v1/agents/tasks/next", headers=agent_auth)
    assert next_task.status_code == 200
    assert next_task.json()["id"] == task["id"]

    nonce = "claim-nonce-0123456789abcdef"
    claimed = client.post(f"/v1/agents/tasks/{task['id']}/claim", headers=agent_auth, json={"nonce": nonce})
    assert claimed.status_code == 200, claimed.text
    assert claimed.json()["state"] == "CLAIMED"

    replay = client.post(f"/v1/agents/tasks/{task['id']}/claim", headers=agent_auth, json={"nonce": nonce})
    assert replay.status_code == 409

    result = client.post(
        f"/v1/agents/tasks/{task['id']}/result",
        headers=agent_auth,
        json={"status": "SUCCEEDED", "summary": "container inventory collected", "evidence": {"stdout_sha256": "a" * 64, "count": 3}},
    )
    assert result.status_code == 200, result.text
    assert result.json()["state"] == "SUCCEEDED"
    assert result.json()["result"]["evidence"]["count"] == 3
    assert "claim_nonce_hash" not in result.json()

    events = client.get("/v1/audit").json()
    assert any(event["event_type"] == "agent.task_issued" and event["subject_id"] == task["id"] for event in events)
    assert any(event["event_type"] == "agent.task_claimed" and event["subject_id"] == task["id"] for event in events)
    assert any(event["event_type"] == "agent.task_completed" and event["subject_id"] == task["id"] for event in events)


def test_agent_task_fails_closed_after_policy_generation_change(client: TestClient):
    env = _env(client)
    target = _agent_target(client, env["id"])
    agent, agent_auth = _enroll_agent(client, ["docker.read"])
    changeset = _previewed_docker_changeset(client, target["id"])

    issued = client.post(
        f"/v1/agents/{agent['id']}/tasks",
        headers=AUTH,
        json={"changeset_id": changeset["id"], "capability": "docker.read"},
    )
    assert issued.status_code == 201, issued.text
    task_id = issued.json()["id"]

    bumped = client.post(
        "/v1/policy-generation/bump",
        headers=AUTH,
        json={"actor": "admin:test", "reason": "agent stale-policy test"},
    )
    assert bumped.status_code == 200

    stale = client.post(
        f"/v1/agents/tasks/{task_id}/claim",
        headers=agent_auth,
        json={"nonce": "claim-nonce-fedcba9876543210"},
    )
    assert stale.status_code == 409
    assert "policy generation is stale" in stale.json()["detail"]
    listed = client.get("/v1/agent-tasks", headers=AUTH).json()
    assert next(row for row in listed if row["id"] == task_id)["state"] == "STALE_POLICY"
