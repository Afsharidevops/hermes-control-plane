from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
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
from hermes_control_plane import kubernetes as kubernetes_broker  # noqa: E402
from hermes_control_plane import radar as radar_provider  # noqa: E402
from hermes_control_plane.main import app  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin"}
CREDENTIAL_SERVICE = {"Authorization": "Bearer test-credential-service"}
FP = "SHA256:" + "R" * 43


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(app) as c:
        yield c


def _cluster(client: TestClient) -> tuple[dict, dict]:
    env_response = client.post("/v1/environments", headers=ADMIN, json={"name": "Radar Runtime", "risk_level": "HIGH"})
    assert env_response.status_code == 201, env_response.text
    env = env_response.json()
    cred_response = client.post(
        "/v1/internal/credential-refs/sync",
        headers=CREDENTIAL_SERVICE,
        json={
            "id": "cred_dev5ssh12345",
            "name": "dev5-ssh",
            "kind": "ssh-key",
            "provider": "credential-service",
            "status": "configured",
            "metadata": {"fingerprint": "sha256:ssh-meta"},
        },
    )
    assert cred_response.status_code == 200, cred_response.text
    server_response = client.post(
        "/v1/servers",
        headers=ADMIN,
        json={
            "hostname": "radar-node-1",
            "environment_id": env["id"],
            "management_ip": "10.55.0.10",
            "ssh_port": 22,
            "ssh_user": "ubuntu",
            "host_fingerprint": FP,
            "connection_mode": "agent",
            "credential_ref": cred_response.json()["id"],
            "labels": {"role": "control-plane-worker"},
        },
    )
    assert server_response.status_code == 201, server_response.text
    blueprint_response = client.post(
        "/v1/cluster-blueprints",
        headers=ADMIN,
        json={
            "name": "dev5-radar-blueprint",
            "provider": "k3s",
            "provider_version": "v1.35.6+k3s1",
            "kubernetes_version": "1.35.6",
            "network_plugin": "cilium",
            "hubble_enabled": False,
            "radar_enabled": True,
            "addon_versions": {
                "cilium": "1.18.1",
                "radar": "1.8.4",
                "hermes-agent": "0.5.11-dev.5",
            },
        },
    )
    assert blueprint_response.status_code == 201, blueprint_response.text
    profile_response = client.post(
        "/v1/cluster-profiles",
        headers=ADMIN,
        json={
            "name": "dev5-radar-profile",
            "environment_id": env["id"],
            "blueprint_id": blueprint_response.json()["id"],
            "server_ids": [server_response.json()["id"]],
        },
    )
    assert profile_response.status_code == 201, profile_response.text
    cluster_response = client.post(
        "/v1/clusters",
        headers=ADMIN,
        json={
            "name": "dev5-radar-cluster",
            "environment_id": env["id"],
            "profile_id": profile_response.json()["id"],
            "labels": {"team": "platform"},
        },
    )
    assert cluster_response.status_code == 201, cluster_response.text
    return env, cluster_response.json()


def _radar_integration(client: TestClient, env: dict) -> dict:
    response = client.post(
        "/v1/integrations",
        headers=ADMIN,
        json={
            "name": "radar-primary",
            "kind": "radar",
            "environment_id": env["id"],
            "endpoint": "http://radar.internal:9280/mcp",
            "connection_mode": "direct",
            "allowed_scope": {"read_only": True},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _native_target(client: TestClient, env: dict) -> dict:
    credential = client.post(
        "/v1/internal/credential-refs/sync",
        headers=CREDENTIAL_SERVICE,
        json={
            "id": "cred_dev5kube1234",
            "name": "dev5-kubeconfig",
            "kind": "kubeconfig",
            "provider": "credential-service",
            "status": "configured",
            "metadata": {"sha256": "0" * 64},
        },
    )
    assert credential.status_code == 200, credential.text
    response = client.post(
        "/v1/targets",
        headers=ADMIN,
        json={
            "name": "dev5-native-k8s",
            "kind": "kubernetes",
            "environment_id": env["id"],
            "credential_ref": credential.json()["id"],
            "connection_mode": "direct",
            "scope": {"namespace_allowlist": ["default"]},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_radar_mcp_initializes_calls_fixed_read_tool_and_redacts() -> None:
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content.decode())
        seen.append({"payload": payload, "headers": dict(request.headers)})
        if payload["method"] == "initialize":
            return httpx.Response(
                200,
                headers={"content-type": "application/json", "Mcp-Session-Id": "session-123"},
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"protocolVersion": "2025-03-26", "serverInfo": {"name": "radar", "version": "1.8.4"}},
                },
            )
        if payload["method"] == "notifications/initialized":
            return httpx.Response(202)
        assert payload["method"] == "tools/call"
        assert payload["params"]["name"] == "list_resources"
        assert request.headers["Mcp-Session-Id"] == "session-123"
        provider_payload = {
            "kind": "Deployment",
            "metadata": {"name": "api", "namespace": "default"},
            "spec": {"template": {"spec": {"containers": [{"name": "api", "env": [{"name": "PASSWORD", "value": "super-secret"}]}]}}},
            "nested_secret": {"kind": "Secret", "metadata": {"name": "db"}, "data": {"password": "c2VjcmV0"}},
            "authorization": "Bearer abc.def.ghi",
        }
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"content": [{"type": "text", "text": json.dumps(provider_payload)}]},
            },
        )

    result = __import__("asyncio").run(
        radar_provider.query(
            "http://radar.internal:9280/mcp",
            "list_resources",
            {"kind": "Deployment", "namespace": "default"},
            transport=httpx.MockTransport(handler),
        )
    )
    assert [entry["payload"]["method"] for entry in seen] == ["initialize", "notifications/initialized", "tools/call"]
    text = result["result"]["content"][0]["text"]
    decoded = json.loads(text)
    assert decoded["spec"]["template"]["spec"]["containers"][0]["env"][0]["value"] == "[REDACTED]"
    assert decoded["nested_secret"] == "[REDACTED]"
    assert decoded["authorization"] == "[REDACTED]"
    assert "super-secret" not in json.dumps(result)
    assert "abc.def.ghi" not in json.dumps(result)


def test_radar_allowlist_rejects_write_tools_and_hidden_mutation_arguments() -> None:
    try:
        radar_provider.validate_read_tool("apply_resource", {"yaml": "kind: Pod"})
    except radar_provider.RadarProtocolError as exc:
        assert "not allowlisted" in str(exc)
    else:
        raise AssertionError("write tool must be rejected")

    try:
        radar_provider.validate_read_tool("get_resource", {"kind": "Pod", "name": "p", "inCluster": True})
    except radar_provider.RadarProtocolError as exc:
        assert "unsupported Radar arguments" in str(exc)
    else:
        raise AssertionError("unknown/mutating argument must be rejected")


def test_radar_mode_uses_same_environment_integration_and_strict_failure(client: TestClient, monkeypatch) -> None:
    env, cluster = _cluster(client)
    integration = _radar_integration(client, env)

    async def fake_query(endpoint: str, tool: str, arguments: dict, **_: object) -> dict:
        assert endpoint == integration["endpoint"]
        assert tool == "get_dashboard"
        return {"tool": tool, "result": {"content": [{"type": "text", "text": "healthy"}]}}

    monkeypatch.setattr(radar_provider, "query", fake_query)
    response = client.post(
        f"/v1/clusters/{cluster['id']}/intelligence/query",
        headers=ADMIN,
        json={"mode": "RADAR", "tool": "get_dashboard", "arguments": {}, "integration_id": integration["id"]},
    )
    assert response.status_code == 200, response.text
    assert response.json()["provider"] == "radar"
    assert response.json()["fallback"] is False

    async def unavailable(*_: object, **__: object) -> dict:
        raise radar_provider.RadarUnavailable("connection refused")

    monkeypatch.setattr(radar_provider, "query", unavailable)
    failed = client.post(
        f"/v1/clusters/{cluster['id']}/intelligence/query",
        headers=ADMIN,
        json={"mode": "RADAR", "tool": "get_dashboard", "arguments": {}, "integration_id": integration["id"]},
    )
    assert failed.status_code == 502
    assert "connection refused" in failed.text


def test_auto_falls_back_to_native_and_redacts_workload_env_values(client: TestClient, monkeypatch) -> None:
    env, cluster = _cluster(client)
    integration = _radar_integration(client, env)
    target = _native_target(client, env)

    async def unavailable(*_: object, **__: object) -> dict:
        raise radar_provider.RadarUnavailable("radar down")

    async def native_post(path: str, payload: dict) -> dict:
        assert path == "/v1/discover"
        assert payload["target_snapshot"]["id"] == target["id"]
        return {
            "version": {"serverVersion": {"gitVersion": "v1.35.6"}},
            "namespaces": {"items": [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "default"}}]},
            "nodes": None,
            "workloads": {
                "items": [
                    {
                        "apiVersion": "apps/v1",
                        "kind": "Deployment",
                        "metadata": {"name": "api", "namespace": "default"},
                        "spec": {"replicas": 2, "template": {"spec": {"containers": [{"name": "api", "env": [{"name": "DB_PASSWORD", "value": "do-not-leak"}]}]}}},
                        "status": {"replicas": 2, "readyReplicas": 1},
                    }
                ]
            },
            "secret_data_requested": False,
        }

    monkeypatch.setattr(radar_provider, "query", unavailable)
    monkeypatch.setattr(kubernetes_broker, "post", native_post)
    response = client.post(
        f"/v1/clusters/{cluster['id']}/intelligence/query",
        headers=ADMIN,
        json={
            "mode": "AUTO",
            "tool": "list_resources",
            "arguments": {"kind": "Deployment", "namespace": "default"},
            "integration_id": integration["id"],
            "native_target_id": target["id"],
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["provider"] == "native"
    assert body["fallback"] is True
    assert body["radar_error"] == "radar down"
    serialized = json.dumps(body)
    assert "do-not-leak" not in serialized
    assert "[REDACTED]" in serialized


def test_native_mode_never_contacts_radar(client: TestClient, monkeypatch) -> None:
    env, cluster = _cluster(client)
    target = _native_target(client, env)

    async def forbidden(*_: object, **__: object) -> dict:
        raise AssertionError("NATIVE mode must not call Radar")

    async def native_post(path: str, payload: dict) -> dict:
        return {"namespaces": {"items": []}, "nodes": None, "workloads": {"items": []}, "secret_data_requested": False}

    monkeypatch.setattr(radar_provider, "query", forbidden)
    monkeypatch.setattr(kubernetes_broker, "post", native_post)
    response = client.post(
        f"/v1/clusters/{cluster['id']}/intelligence/query",
        headers=ADMIN,
        json={"mode": "NATIVE", "tool": "get_dashboard", "arguments": {}, "native_target_id": target["id"]},
    )
    assert response.status_code == 200, response.text
    assert response.json()["provider"] == "native"
    assert response.json()["fallback"] is False


def test_intelligence_rejects_cross_environment_native_target(client: TestClient, monkeypatch) -> None:
    env, cluster = _cluster(client)
    other = client.post("/v1/environments", headers=ADMIN, json={"name": "Other Env", "risk_level": "LOW"}).json()
    target = _native_target(client, other)

    async def forbidden(*_: object, **__: object) -> dict:
        raise AssertionError("NATIVE mode must not call Radar")

    monkeypatch.setattr(radar_provider, "query", forbidden)
    response = client.post(
        f"/v1/clusters/{cluster['id']}/intelligence/query",
        headers=ADMIN,
        json={"mode": "NATIVE", "tool": "get_dashboard", "arguments": {}, "native_target_id": target["id"]},
    )
    assert response.status_code == 403
    assert "different environment" in response.text
