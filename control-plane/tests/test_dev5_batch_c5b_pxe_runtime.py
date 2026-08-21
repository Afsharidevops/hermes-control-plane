from __future__ import annotations

import hashlib
import json
import os
from contextlib import closing
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

from hermes_control_plane import cluster_factory, db, provider_worker  # noqa: E402
from hermes_control_plane.main import app  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin"}
BOT = {"Authorization": "Bearer test-bot"}
APPROVAL = {"Authorization": "Bearer test-approval"}
CREDENTIAL_SERVICE = {"Authorization": "Bearer test-credential-service"}
FP = "SHA256:" + "C" * 43


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(app) as c:
        yield c


def _credential(client: TestClient, credential_id: str, *, kind: str = "generic") -> dict:
    response = client.post(
        "/v1/internal/credential-refs/sync", headers=CREDENTIAL_SERVICE,
        json={
            "id": credential_id, "name": credential_id, "kind": kind,
            "provider": "credential-service", "status": "configured",
            "metadata": {"scope": "infrastructure-provider-worker"},
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _provider(client: TestClient, *, kind: str, name: str, credential_ref: str, endpoint: str, capabilities: dict) -> dict:
    response = client.post(
        "/v1/infrastructure-providers", headers=ADMIN,
        json={
            "name": name, "kind": kind, "endpoint": endpoint, "credential_ref": credential_ref,
            "api_version": "v1", "implementation_version": f"{kind}-trusted-v1",
            "site": "dc1", "zone": "rack-a", "capabilities": capabilities,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _artifact(client: TestClient, role: str, index: int) -> dict:
    digest = "sha256:" + format(index, "064x")
    response = client.post(
        "/v1/artifact-mirror/items", headers=ADMIN,
        json={
            "name": f"pxe-{role}", "kind": "package", "source": f"https://source.example/{role}",
            "destination": f"file:///data/artifact-mirror/pxe/{role}", "version": "1.0", "digest": digest,
            "labels": {"pxe_role": role},
        },
    )
    assert response.status_code == 201, response.text
    item = response.json()
    verification = {
        "verification_id": f"ver_{item['id'][4:]}", "status": "PASS", "sync_state": "MIRRORED",
        "checks": [{"id": "destination-digest", "status": "PASS"}], "observed_at": 1787330000,
    }
    with closing(db.connect()) as conn:
        conn.execute("UPDATE artifact_mirror_items SET verification_json=? WHERE id=?", (json.dumps(verification, sort_keys=True), item["id"]))
        conn.commit()
    return item


def _fixture(client: TestClient) -> tuple[dict, dict, dict, dict[str, dict]]:
    ssh = _credential(client, "cred_serverssh12345", kind="ssh-key")
    boot_cred = _credential(client, "cred_redfish12345")
    pxe_cred = _credential(client, "cred_pxecontroller1")
    boot = _provider(
        client, kind="redfish", name="rack-a-bmc", credential_ref=boot_cred["id"],
        endpoint="https://bmc.internal.example/redfish/v1", capabilities={"system_id": "System.Embedded.1"},
    )
    pxe = _provider(
        client, kind="pxe", name="private-pxe", credential_ref=pxe_cred["id"],
        endpoint="https://pxe.internal.example/v1", capabilities={"network_scope": "private-offline", "artifact_delivery": "shared-readonly-mirror"},
    )
    env = client.post("/v1/environments", headers=ADMIN, json={"name": "PXE Offline", "risk_level": "HIGH"}).json()
    server_response = client.post(
        "/v1/servers", headers=ADMIN,
        json={
            "hostname": "node01.example.internal", "environment_id": env["id"], "management_ip": "10.70.0.11",
            "provisioning_ip": "10.71.0.11", "bmc_ip": "10.72.0.11", "host_fingerprint": FP,
            "connection_mode": "agent", "credential_ref": ssh["id"], "architecture": "amd64", "site": "dc1", "rack": "rack-a",
            "labels": {"provisioning_mac": "52:54:00:12:34:56", "provisioning_nic": "eno1", "boot_provider_id": boot["id"], "api_token": "never-copy-me"},
        },
    )
    assert server_response.status_code == 201, server_response.text
    artifacts = {role: _artifact(client, role, index) for index, role in enumerate(("kernel", "initrd", "unattended"), 201)}
    return pxe, boot, server_response.json(), artifacts


def _desired(artifacts: dict[str, dict]) -> dict:
    callback = hashlib.sha256(b"worker-side-callback-token").hexdigest()
    return {
        "boot_method": "ipxe", "boot_mode": "uefi",
        "artifacts": {role: item["id"] for role, item in artifacts.items()},
        "unattended_profile_ref": "profile_ubuntu", "callback_ref": "callback_node01",
        "callback_token_sha256": callback, "completion_timeout_seconds": 600, "host_ready_timeout_seconds": 60,
    }


def _runtime_preview(preliminary: dict) -> dict:
    targets = preliminary["targets"]
    server = next(target for target in targets if target.get("entity_type") == "server")
    boot = next(target for target in targets if target.get("kind") in {"redfish", "ipmi"})
    current = {
        "controller": {
            "registered": False, "node_id": server["id"], "nic": server["labels"]["provisioning_nic"],
            "mac": server["labels"]["provisioning_mac"], "state": "idle", "state_history": [], "plan_hash": "",
            "artifact_manifest_hash": "", "callback_token_sha256": "", "management_ip": "",
        },
        "boot_provider": {
            "provider_kind": boot["kind"], "resource_id": "System.Embedded.1", "power_state": "On",
            "boot_target": "Hdd", "boot_enabled": "Disabled", "boot_mode": "UEFI",
        },
    }
    current_hash = hashlib.sha256(json.dumps(current, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return {
        "kind": "InfrastructureRuntimePreview", "provider_kind": "pxe", "operation": preliminary["operation"],
        "typed_plan_hash": preliminary["plan_hash"], "current": current, "current_hash": current_hash,
        "desired_state": preliminary["desired_state"], "diff": [{"field": "provisioning_state", "from": "idle", "to": "complete"}],
        "active_probe": True, "credential_material_returned": False, "secret_output_suppressed": True,
        "arbitrary_cli": False, "arbitrary_shell": False,
    }


def _approve(client: TestClient, changeset: dict) -> None:
    requested = client.post(f"/v1/changesets/{changeset['id']}/request-approval", headers=BOT)
    assert requested.status_code == 200, requested.text
    approved = client.post(
        f"/v1/changesets/{changeset['id']}/approve", headers=APPROVAL,
        json={"approver": "approval-bot:pxe", "plan_hash": changeset["plan_hash"]},
    )
    assert approved.status_code == 201, approved.text


def test_pxe_artifact_manifest_requires_exact_ready_local_mirror():
    artifacts = [
        {"id": "art_0000000000000001", "kind": "package", "version": "1", "digest": "sha256:" + "1" * 64,
         "destination": "file:///data/artifact-mirror/kernel", "verification": {"status": "PASS", "sync_state": "MIRRORED"}},
        {"id": "art_0000000000000002", "kind": "package", "version": "1", "digest": "sha256:" + "2" * 64,
         "destination": "file:///data/artifact-mirror/initrd", "verification": {"status": "PASS", "sync_state": "MIRRORED"}},
        {"id": "art_0000000000000003", "kind": "package", "version": "1", "digest": "sha256:" + "3" * 64,
         "destination": "file:///data/artifact-mirror/unattended", "verification": {"status": "PASS", "sync_state": "MIRRORED"}},
    ]
    bindings = {"kernel": artifacts[0]["id"], "initrd": artifacts[1]["id"], "unattended": artifacts[2]["id"]}
    manifest = cluster_factory.resolve_pxe_artifact_manifest(role_bindings=bindings, artifacts=artifacts)
    assert manifest["state"] == "READY"
    supply = cluster_factory.pxe_artifact_supply(manifest)
    assert supply["mode"] == "pxe-ready-manifest-bound"
    assert supply["public_network_required"] is False
    assert supply["credential_material_in_plan"] is False

    artifacts[0]["destination"] = "https://public.example/kernel"
    blocked = cluster_factory.resolve_pxe_artifact_manifest(role_bindings=bindings, artifacts=artifacts)
    assert blocked["state"] == "BLOCKED"
    with pytest.raises(ValueError):
        cluster_factory.pxe_artifact_supply(blocked)


def test_pxe_plan_binds_server_boot_provider_and_ready_artifacts(client: TestClient, monkeypatch):
    pxe, boot, server, artifacts = _fixture(client)
    seen = []

    async def fake_post(path, payload):
        assert path == "/v1/infrastructure/preview"
        preliminary = payload["changeset_plan"]["parameters"]["typed_plan"]
        seen.append(preliminary)
        return _runtime_preview(preliminary)

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:pxe", "source_channel": "hermes-bot", "domain": "bare-metal",
            "operation": "os.provision", "provider_id": pxe["id"], "target_id": server["id"], "desired_state": _desired(artifacts),
        },
    )
    assert planned.status_code == 201, planned.text
    body = planned.json()
    assert body["operation_job"]["executor"] == "infrastructure-provider-worker"
    plan = body["operation_plan"]["plan"]
    assert plan["runtime"]["state"] == "RUNTIME_CAPABLE"
    assert plan["artifact_supply"]["mode"] == "pxe-ready-manifest-bound"
    assert plan["artifact_supply"]["public_network_required"] is False
    assert plan["credential_material_in_plan"] is False
    assert {target["id"] for target in plan["targets"]} == {pxe["id"], boot["id"], server["id"]}
    encoded = json.dumps(plan)
    assert "worker-side-callback-token" not in encoded
    assert "password" not in encoded.lower()
    assert "never-copy-me" not in encoded
    server_target = next(target for target in plan["targets"] if target.get("entity_type") == "server")
    assert set(server_target["labels"]) == {"provisioning_mac", "provisioning_nic", "boot_provider_id"}
    assert seen


def test_pxe_planning_rejects_non_private_controller_scope_before_worker(client: TestClient, monkeypatch):
    pxe, _, server, artifacts = _fixture(client)
    with closing(db.connect()) as conn:
        conn.execute("UPDATE infrastructure_providers SET capabilities_json=? WHERE id=?", (json.dumps({}), pxe["id"]))
        conn.commit()
    called = []
    monkeypatch.setattr(provider_worker, "post", lambda *args, **kwargs: called.append(True))
    denied = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:pxe", "source_channel": "hermes-bot", "domain": "bare-metal",
            "operation": "os.provision", "provider_id": pxe["id"], "target_id": server["id"], "desired_state": _desired(artifacts),
        },
    )
    assert denied.status_code == 409
    assert "private-offline" in denied.text
    assert called == []


def test_pxe_authorization_rejects_artifact_verification_drift(client: TestClient, monkeypatch):
    pxe, _, server, artifacts = _fixture(client)

    async def fake_post(path, payload):
        return _runtime_preview(payload["changeset_plan"]["parameters"]["typed_plan"])

    monkeypatch.setattr(provider_worker, "post", fake_post)
    planned = client.post(
        "/v1/operations-center/intents/plan", headers=BOT,
        json={
            "requested_by": "hermes-bot:pxe", "source_channel": "hermes-bot", "domain": "bare-metal",
            "operation": "os.provision", "provider_id": pxe["id"], "target_id": server["id"], "desired_state": _desired(artifacts),
        },
    )
    assert planned.status_code == 201, planned.text
    body = planned.json()
    _approve(client, body["changeset"])
    victim = artifacts["kernel"]["id"]
    with closing(db.connect()) as conn:
        verification = {"verification_id": "ver_drift", "status": "FAIL", "sync_state": "FAILED", "checks": [], "observed_at": 1787330100}
        conn.execute("UPDATE artifact_mirror_items SET verification_json=? WHERE id=?", (json.dumps(verification, sort_keys=True), victim))
        conn.commit()
    denied = client.post(f"/v1/operation-jobs/{body['operation_job']['id']}/authorize", headers=BOT)
    assert denied.status_code == 409
    assert "artifact manifest" in denied.text.lower()
