from __future__ import annotations

from pathlib import Path
import re
import yaml

ROOT = Path(__file__).resolve().parents[2]


def load_yaml(path: str):
    raw = (ROOT / path).read_text()
    yaml.compose(raw)
    return yaml.safe_load(raw)


chart = load_yaml("charts/hermes-control-plane/Chart.yaml")
values = load_yaml("charts/hermes-control-plane/values.yaml")
assert chart["version"] == "0.5.11-dev.3"
assert str(chart["appVersion"]) == "0.5.11-dev.3"
assert str(values["imageTag"]) == "0.5.11-dev.3"

compose = load_yaml("docker-compose.yml")
assert isinstance(compose, dict) and isinstance(compose.get("services"), dict)
services = compose["services"]
for required in ("control-plane", "credential-service", "router-gateway", "smart-router", "kubernetes-broker", "hermes", "node-agent"):
    assert required in services, required
assert (compose.get("networks") or {}).get("credential-net", {}).get("internal") is True
for llm_service in ("smart-router", "hermes", "router-gateway"):
    assert "HERMES_CREDENTIAL_MASTER_KEY" not in yaml.safe_dump(services[llm_service])

# Cluster Factory is integrated into the existing control-plane service; no untracked deployable service was introduced.
publish = (ROOT / ".github/workflows/publish-images.yml").read_text()
contexts = re.findall(r"context:\s+\./([A-Za-z0-9_-]+)", publish)
assert set(contexts) == {"control-plane", "credential-service", "router-gateway", "smart-router", "execution-broker", "kubernetes-broker", "node-agent"}
for context in contexts:
    assert (ROOT / context / "Dockerfile").is_file(), context

# Persist all eight first-class lifecycle resource families plus intelligence snapshots.
db = (ROOT / "control-plane/src/hermes_control_plane/db.py").read_text()
for table in (
    "cluster_blueprints", "cluster_profiles", "clusters", "node_roles", "provisioning_runs",
    "addon_plans", "upgrade_plans", "backup_plans", "kubernetes_intelligence_snapshots",
):
    assert f"CREATE TABLE IF NOT EXISTS {table}" in db, table
assert "PRAGMA user_version = 7" in db
assert "provider_version TEXT NOT NULL" in db
assert "addon_versions_json TEXT NOT NULL" in db

providers = (ROOT / "control-plane/src/hermes_control_plane/providers.py").read_text()
assert '"status": "dev3-production-path"' in providers
assert '"status": "dev3-lab-edge-path"' in providers
assert '"status": "dev3-hardened-path"' in providers
assert '"plan_contract": "KubesprayExecutionSpec"' in providers
assert '"plan_contract": "K3sExecutionSpec"' in providers
assert '"plan_contract": "RKE2ExecutionSpec"' in providers
assert providers.count('"provider_version_pin": "required"') >= 3

for workflow_path in (".github/workflows/validate.yml", ".github/workflows/publish-images.yml"):
    load_yaml(workflow_path)
validate_workflow = (ROOT / ".github/workflows/validate.yml").read_text()
assert "0.5.11-dev.3)" in validate_workflow
assert "scripts/acceptance/dev3-source-security-gate.py" in validate_workflow
assert "scripts/acceptance/dev3-config-static-gate.py" in validate_workflow
for script in ("apply.sh", "validate.sh", "push.sh"):
    raw = (ROOT / script).read_text()
    assert "<<<<<<<" not in raw and ">>>>>>>" not in raw

print("0.5.11-dev.3-config-static: PASS")
