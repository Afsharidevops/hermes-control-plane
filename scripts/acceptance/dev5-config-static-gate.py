from __future__ import annotations

from pathlib import Path
import hashlib
import re
import yaml

ROOT = Path(__file__).resolve().parents[2]


def load_yaml(path: str):
    raw = (ROOT / path).read_text()
    yaml.compose(raw)
    return yaml.safe_load(raw)


chart = load_yaml("charts/hermes-control-plane/Chart.yaml")
values = load_yaml("charts/hermes-control-plane/values.yaml")
assert chart["version"] == "0.5.11-dev.5"
assert str(chart["appVersion"]) == "0.5.11-dev.5"
assert str(values["imageTag"]) == "0.5.11-dev.5"
assert "VERSION=0.5.11-dev.5" in (ROOT / ".env.example").read_text()

compose = load_yaml("docker-compose.yml")
assert isinstance(compose, dict) and isinstance(compose.get("services"), dict)
services = compose["services"]
for required in ("control-plane", "credential-service", "router-gateway", "smart-router", "kubernetes-broker", "hermes", "node-agent"):
    assert required in services, required
assert (compose.get("networks") or {}).get("credential-net", {}).get("internal") is True
for llm_service in ("smart-router", "hermes", "router-gateway"):
    assert "HERMES_CREDENTIAL_MASTER_KEY" not in yaml.safe_dump(services[llm_service])

publish = (ROOT / ".github/workflows/publish-images.yml").read_text()
contexts = re.findall(r"context:\s+\./([A-Za-z0-9_-]+)", publish)
assert set(contexts) == {"control-plane", "credential-service", "router-gateway", "smart-router", "execution-broker", "kubernetes-broker", "node-agent"}
for context in contexts:
    assert (ROOT / context / "Dockerfile").is_file(), context

# Dev.4 persistence remains; dev.5 adds bounded sanitized Hubble flow history.
db = (ROOT / "control-plane/src/hermes_control_plane/db.py").read_text()
for table in (
    "cluster_blueprints", "cluster_profiles", "clusters", "node_roles", "provisioning_runs",
    "addon_plans", "upgrade_plans", "backup_plans", "kubernetes_intelligence_snapshots",
    "infrastructure_providers", "fleet_target_snapshots", "operation_plans", "operation_jobs",
    "artifact_mirror_items", "verification_results", "hubble_flow_events",
):
    assert f"CREATE TABLE IF NOT EXISTS {table}" in db, table
assert "PRAGMA user_version = 10" in db

main = (ROOT / "control-plane/src/hermes_control_plane/main.py").read_text()
models = (ROOT / "control-plane/src/hermes_control_plane/models.py").read_text()
radar = (ROOT / "control-plane/src/hermes_control_plane/radar.py").read_text()
assert 'VERSION = "0.5.11-dev.5"' in main
assert 'class RadarIntelligenceQuery' in models
assert '"tools/call"' in radar
assert 'MCP_PROTOCOL_VERSION' in radar

ui = (ROOT / "control-plane/src/hermes_control_plane/static/index.html").read_text()
assert "0.5.11-dev.5" in ui
assert "Query live intelligence" in ui
assert "radar-mode" in ui
assert "/intelligence/query" in ui
assert "Collect Network Live" in ui
assert "/network/live" in ui
assert "Run Native Diagnostics" in ui
assert "Run unified verification" in ui
assert "/v1/clusters/${cluster}/verify" in ui
assert "/diagnostics/run" in ui
assert "native-diagnostics" in ui
assert "<option>radar</option>" in ui
assert "Operator Center" in ui
assert "/v1/operator-center/contracts" in ui
assert "refreshOperatorCenter" in ui
assert "runtime/provider state" in ui

for workflow_path in (".github/workflows/validate.yml", ".github/workflows/publish-images.yml"):
    load_yaml(workflow_path)
validate_workflow = (ROOT / ".github/workflows/validate.yml").read_text()
assert "0.5.11-dev.5)" in validate_workflow
assert "'dev/**'" in validate_workflow
assert "'dev/**'" not in publish
assert "pull_request:" not in publish
assert "branches: [main]" in publish
assert "scripts/acceptance/dev5-source-security-gate.py" in validate_workflow
assert "scripts/acceptance/dev5-config-static-gate.py" in validate_workflow

for script in ("apply.sh", "validate.sh", "push.sh"):
    raw = (ROOT / script).read_text()
    assert "<<<<<<<" not in raw and ">>>>>>>" not in raw
    assert "0.5.11-dev.5" in raw
    assert "d4eb9b7ab2564301c09b8c0d36a2e9d53b843273" in raw if script != "validate.sh" else True

assert (ROOT / "docs/DEV5-SCOPE-CLOSURE.md").is_file()
assert (ROOT / "control-plane/tests/test_dev5_radar_runtime.py").is_file()
assert (ROOT / "control-plane/tests/test_dev5_hubble_runtime.py").is_file()
assert (ROOT / "control-plane/tests/test_dev5_diagnostics_runtime.py").is_file()
assert (ROOT / "control-plane/tests/test_dev5_operator_ui.py").is_file()
assert (ROOT / "control-plane/tests/test_dev5_day2_runtime.py").is_file()
assert (ROOT / "control-plane/tests/test_dev5_unified_verification.py").is_file()
assert (ROOT / "control-plane/src/hermes_control_plane/verification.py").is_file()
assert (ROOT / "control-plane/tests/test_dev5_artifact_mirror_runtime.py").is_file()
assert (ROOT / "control-plane/src/hermes_control_plane/artifact_mirror.py").is_file()
assert (ROOT / "control-plane/tests/test_dev5_blueprint_artifact_resolver.py").is_file()
assert (ROOT / "control-plane/tests/test_dev5_git_release_mirror_runtime.py").is_file()
assert (ROOT / "control-plane/tests/test_dev5_ansible_collection_mirror_runtime.py").is_file()
assert (ROOT / "control-plane/tests/test_dev5_repository_snapshot_runtime.py").is_file()
assert (ROOT / "control-plane/src/hermes_control_plane/repository_snapshot.py").is_file()
cluster_factory = (ROOT / "control-plane/src/hermes_control_plane/cluster_factory.py").read_text()
assert "resolve_blueprint_artifact_manifest" in cluster_factory
assert "credential_material_in_manifest" in cluster_factory
assert "provisioner_rewrite_applied" in cluster_factory
assert '"artifact_dependencies_json"' in db
assert "oci_registry_mirror" in (ROOT / "control-plane/tests/test_dev5_artifact_mirror_runtime.py").read_text()
assert "git_release" in (ROOT / "control-plane/tests/test_dev5_git_release_mirror_runtime.py").read_text()
assert services["control-plane"]["environment"]["HERMES_ARTIFACT_SOURCE_ROOT"] == "/data/artifact-source"
assert services["control-plane"]["environment"]["HERMES_ARTIFACT_MIRROR_ROOT"] == "/data/artifact-mirror"
assert "HERMES_ARTIFACT_HTTPS_HOST_ALLOWLIST" in services["control-plane"]["environment"]
assert "HERMES_ARTIFACT_OCI_SOURCE_REGISTRY_ALLOWLIST" in services["control-plane"]["environment"]
assert "HERMES_ARTIFACT_OCI_DESTINATION_REGISTRY_ALLOWLIST" in services["control-plane"]["environment"]
for env_name in (
    "HERMES_ARTIFACT_AUTH_ROOT", "HERMES_ARTIFACT_HTTPS_AUTHFILE", "HERMES_ARTIFACT_REPOSITORY_KEYRING",
    "HERMES_ARTIFACT_OCI_SOURCE_AUTHFILE", "HERMES_ARTIFACT_OCI_DESTINATION_AUTHFILE",
    "HERMES_ARTIFACT_REPOSITORY_MAX_EXPANDED_BYTES", "HERMES_ARTIFACT_REPOSITORY_METADATA_MAX_BYTES",
):
    assert env_name in services["control-plane"]["environment"], env_name
assert values["controlPlane"]["artifactMirror"]["authSecretName"] == ""
assert values["controlPlane"]["artifactMirror"]["httpsAuthFile"] == ""
assert values["controlPlane"]["artifactMirror"]["repositoryKeyringFile"] == ""
assert values["controlPlane"]["artifactMirror"]["ociSourceRegistryAllowlist"] == ""
assert values["controlPlane"]["artifactMirror"]["ociDestinationRegistryAllowlist"] == ""
assert values["controlPlane"]["artifactMirror"]["maxBytes"] == 536870912
assert values["controlPlane"]["artifactMirror"]["timeoutSeconds"] == 60
assert values["controlPlane"]["artifactMirror"]["repositoryMaxExpandedBytes"] == 4294967296
assert values["controlPlane"]["artifactMirror"]["repositoryMetadataMaxBytes"] == 268435456
assert (ROOT / "kubernetes-broker/tests/test_day2_runtime.py").is_file()
day2_tests = (ROOT / "kubernetes-broker/tests/test_day2_runtime.py").read_text() + (ROOT / "control-plane/tests/test_dev5_day2_runtime.py").read_text()
assert "cluster.gitops.sync" in day2_tests
assert "cluster.cilium.upgrade" in day2_tests
assert "cluster.backup.velero" in day2_tests
assert "cluster.backup.schedule" in day2_tests
assert "cluster.restore" in day2_tests
assert 'required_approvals"] == 2' in day2_tests
assert (ROOT / "control-plane/src/hermes_control_plane/operator_center.py").is_file()
assert (ROOT / "kubernetes-broker/src/hermes_kubernetes_broker/hubble.py").is_file()
assert (ROOT / "kubernetes-broker/src/hermes_kubernetes_broker/diagnostics.py").is_file()

# The source manifest is a complete checksum inventory of every managed file except itself.
manifest_path = ROOT / "MANIFEST.sha256"
manifest_entries: dict[str, str] = {}
for line in manifest_path.read_text().splitlines():
    digest, rel = line.split("  ", 1)
    assert re.fullmatch(r"[0-9a-f]{64}", digest), rel
    assert rel not in manifest_entries, rel
    manifest_entries[rel] = digest

LOCAL_ONLY_TOP_LEVEL = {".git", "backups", "htmlcov", "node_modules"}
LOCAL_ONLY_ANYWHERE = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
LOCAL_ONLY_ROOT_FILES = {".env", ".coverage"}


def is_managed_inventory_file(path: Path) -> bool:
    if not path.is_file() or path == manifest_path or path.suffix == ".pyc":
        return False
    rel = path.relative_to(ROOT)
    parts = rel.parts
    if not parts:
        return False
    if parts[0] in LOCAL_ONLY_TOP_LEVEL or parts[0].startswith(".venv"):
        return False
    if any(part in LOCAL_ONLY_ANYWHERE for part in parts):
        return False
    if rel.as_posix() in LOCAL_ONLY_ROOT_FILES:
        return False
    if parts[0] == "data" and path.name != ".gitkeep":
        return False
    if parts[0] == "release-evidence" and path.suffix == ".log":
        return False
    return True


actual_files = {
    path.relative_to(ROOT).as_posix()
    for path in ROOT.rglob("*")
    if is_managed_inventory_file(path)
}
assert set(manifest_entries) == actual_files, (
    "manifest inventory drift",
    sorted(actual_files - set(manifest_entries)),
    sorted(set(manifest_entries) - actual_files),
)
for rel, expected in manifest_entries.items():
    actual = hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()
    assert actual == expected, f"manifest digest mismatch: {rel}"

print("0.5.11-dev.5-config-static: PASS")
