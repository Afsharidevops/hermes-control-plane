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


@pytest.fixture()
def client(tmp_path: Path):
    db.DB_PATH = tmp_path / "control.sqlite3"
    with TestClient(app) as c:
        yield c


def _surface_map(body: dict) -> dict[str, dict]:
    return {
        surface["id"]: surface
        for group in body["groups"]
        for surface in group["surfaces"]
    }


def test_operator_center_contract_covers_original_navigation_scope(client: TestClient):
    response = client.get("/v1/operator-center/contracts")
    assert response.status_code == 200
    body = response.json()
    assert body["ui_state"] == "IMPLEMENTED"
    assert body["runtime_state_is_separate_from_ui_state"] is True
    assert body["credential_material_rendered"] is False
    assert body["mutation_ui"] == "observe-plan-inspect-only"

    groups = {group["id"]: group for group in body["groups"]}
    assert set(groups) == {"kubernetes", "cluster-factory", "infrastructure", "operations", "governance"}

    surfaces = _surface_map(body)
    required = {
        "kubernetes.overview", "kubernetes.issues", "kubernetes.applications", "kubernetes.topology",
        "kubernetes.network-live", "kubernetes.resources", "kubernetes.workloads", "kubernetes.nodes",
        "kubernetes.storage", "kubernetes.ingress", "kubernetes.metrics", "kubernetes.logs",
        "kubernetes.timeline", "kubernetes.helm", "kubernetes.gitops", "kubernetes.cost",
        "kubernetes.tls", "kubernetes.security", "kubernetes.rbac", "kubernetes.audit",
        "cluster-factory.clusters", "cluster-factory.servers", "cluster-factory.provision",
        "cluster-factory.templates", "cluster-factory.bare-metal", "cluster-factory.images-artifacts",
        "infrastructure.kubernetes", "infrastructure.vmware", "infrastructure.openstack",
        "infrastructure.aws", "infrastructure.azure", "infrastructure.gcp", "infrastructure.docker",
        "infrastructure.swarm", "infrastructure.ssh", "operations.diagnostics",
        "operations.deployments", "operations.upgrades", "operations.backups", "operations.recovery",
        "operations.maintenance", "governance.changes", "governance.approvals",
        "governance.credentials", "governance.agents", "governance.integrations",
        "governance.artifact-mirror", "governance.audit", "governance.ai-routing",
        "governance.settings",
    }
    assert required <= set(surfaces)
    assert body["surface_count"] == len(surfaces)
    assert all(surface["ui_state"] == "IMPLEMENTED" for surface in surfaces.values())


def test_operator_center_does_not_upgrade_contract_only_runtime_to_live(client: TestClient):
    surfaces = _surface_map(client.get("/v1/operator-center/contracts").json())
    for surface_id in (
        "infrastructure.vmware",
        "infrastructure.openstack",
        "infrastructure.aws",
        "infrastructure.azure",
        "infrastructure.gcp",
        "cluster-factory.bare-metal",
    ):
        assert surfaces[surface_id]["runtime_state"] == "CONTRACT_ONLY"
    assert surfaces["governance.artifact-mirror"]["runtime_state"] == "LIVE"
    assert surfaces["cluster-factory.images-artifacts"]["runtime_state"] == "LIVE"
    assert surfaces["kubernetes.network-live"]["runtime_state"] == "LIVE"
    assert surfaces["operations.diagnostics"]["runtime_state"] == "LIVE"
    assert surfaces["kubernetes.logs"]["runtime_state"] == "PARTIAL"


def test_operator_center_ui_is_read_observe_plan_inspect_only(client: TestClient):
    ui = client.get("/ui")
    assert ui.status_code == 200
    raw = ui.text
    assert "Operator Center" in raw
    assert "refreshOperatorCenter" in raw
    assert "/v1/operator-center/contracts" in raw
    assert "runtime/provider state" in raw
    assert "runOperatorSurfaceDiagnostics" in raw
    assert "collectOperatorNetwork" in raw
    # Operator Center itself must not expose approval/execution/mutation actions.
    operator_section = raw.split('<section id="operator-center"', 1)[1].split('</section>', 1)[0]
    for forbidden in ("approveChange", "executeChange", "createChange", "kubectl", "helm upgrade"):
        assert forbidden not in operator_section


def test_system_advertises_operator_center_ui_capability(client: TestClient):
    body = client.get("/v1/system").json()
    assert "operator-center-ui" in body["capabilities"]
