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
assert chart["version"] == "0.5.11"
assert str(chart["appVersion"]) == "0.5.11"
assert str(values["imageTag"]) == "0.5.11"
assert "VERSION=0.5.11" in (ROOT / ".env.example").read_text()

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
    "artifact_mirror_items", "verification_results", "hubble_flow_events", "server_host_observation_bindings",
):
    assert f"CREATE TABLE IF NOT EXISTS {table}" in db, table
assert "PRAGMA user_version = 11" in db

main = (ROOT / "control-plane/src/hermes_control_plane/main.py").read_text()
models = (ROOT / "control-plane/src/hermes_control_plane/models.py").read_text()
radar = (ROOT / "control-plane/src/hermes_control_plane/radar.py").read_text()
assert 'VERSION = "0.5.11"' in main
assert 'class RadarIntelligenceQuery' in models
assert '"tools/call"' in radar
assert 'MCP_PROTOCOL_VERSION' in radar

ui = (ROOT / "control-plane/src/hermes_control_plane/static/index.html").read_text()
assert "0.5.11" in ui
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
assert "0.5.11)" in validate_workflow
assert "'dev/**'" in validate_workflow
assert "'dev/**'" not in publish
assert "pull_request:" not in publish
assert "branches: [main]" in publish
assert "scripts/acceptance/dev5-source-security-gate.py" in validate_workflow
assert "scripts/acceptance/dev5-config-static-gate.py" in validate_workflow

for script in ("apply.sh", "validate.sh", "push.sh"):
    raw = (ROOT / script).read_text()
    assert "<<<<<<<" not in raw and ">>>>>>>" not in raw
    assert "0.5.11" in raw
    assert "d4eb9b7ab2564301c09b8c0d36a2e9d53b843273" in raw if script != "validate.sh" else True

assert (ROOT / "docs/DEV5-SCOPE-CLOSURE.md").is_file()
assert (ROOT / "docs/PROXMOX-VM-RUNTIME-VALIDATION.md").is_file()
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
assert (ROOT / "control-plane/tests/test_dev5_batch_b_provider_runtime.py").is_file()
assert (ROOT / "node-agent/tests/test_provider_runtime.py").is_file()
assert (ROOT / "node-agent/src/hermes_node_agent/provider_runtime.py").is_file()
assert (ROOT / "node-agent/playbooks/provider-operation.yml").is_file()
assert (ROOT / "node-agent/playbooks/provider-verify.yml").is_file()
node_agent_requirements = (ROOT / "node-agent/requirements.txt").read_text()
for marker in ("ansible==9.13.0", "cryptography==45.0.2", "jmespath==1.0.1", "netaddr==1.3.0"):
    assert marker in node_agent_requirements, marker

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
assert services["control-plane"]["environment"]["HERMES_PROVIDER_WORKER_URL"] == "http://node-agent:8810"
assert "HERMES_PROVIDER_WORKER_TOKEN" in services["control-plane"]["environment"]
assert services["node-agent"]["environment"]["HERMES_PROVIDER_EXECUTION_ENABLED"] == "${HERMES_PROVIDER_EXECUTION_ENABLED:-false}"
assert services["node-agent"]["environment"]["HERMES_INFRASTRUCTURE_EXECUTION_ENABLED"] == "${HERMES_INFRASTRUCTURE_EXECUTION_ENABLED:-false}"
assert services["node-agent"]["environment"]["HERMES_INFRASTRUCTURE_CREDENTIAL_ROOT"] == "/credentials/infrastructure"
assert services["node-agent"]["environment"]["HERMES_INFRASTRUCTURE_ALLOW_HTTP"] == "${HERMES_INFRASTRUCTURE_ALLOW_HTTP:-false}"
assert services["node-agent"]["environment"]["HERMES_INFRASTRUCTURE_IPMI_TIMEOUT_SECONDS"] == "${HERMES_INFRASTRUCTURE_IPMI_TIMEOUT_SECONDS:-20}"
assert services["node-agent"]["environment"]["HERMES_INFRASTRUCTURE_FIRMWARE_VERIFY_ATTEMPTS"] == "${HERMES_INFRASTRUCTURE_FIRMWARE_VERIFY_ATTEMPTS:-60}"
assert services["node-agent"]["environment"]["HERMES_INFRASTRUCTURE_FIRMWARE_VERIFY_DELAY_SECONDS"] == "${HERMES_INFRASTRUCTURE_FIRMWARE_VERIFY_DELAY_SECONDS:-5}"
assert services["node-agent"]["environment"]["HERMES_INFRASTRUCTURE_PLATFORM_VERIFY_ATTEMPTS"] == "${HERMES_INFRASTRUCTURE_PLATFORM_VERIFY_ATTEMPTS:-90}"
assert services["node-agent"]["environment"]["HERMES_INFRASTRUCTURE_PLATFORM_VERIFY_DELAY_SECONDS"] == "${HERMES_INFRASTRUCTURE_PLATFORM_VERIFY_DELAY_SECONDS:-5}"
assert services["node-agent"]["environment"]["HERMES_CAPACITY_COLLECTION_ENABLED"] == "${HERMES_CAPACITY_COLLECTION_ENABLED:-false}"
assert services["node-agent"]["environment"]["HERMES_CAPACITY_REQUEST_TIMEOUT_SECONDS"] == "${HERMES_CAPACITY_REQUEST_TIMEOUT_SECONDS:-20}"
assert services["node-agent"]["environment"]["HERMES_CAPACITY_MAX_RESPONSE_BYTES"] == "${HERMES_CAPACITY_MAX_RESPONSE_BYTES:-1048576}"
assert services["node-agent"]["environment"]["HERMES_CAPACITY_MAX_REQUESTS"] == "${HERMES_CAPACITY_MAX_REQUESTS:-8}"
assert services["control-plane"]["environment"]["HERMES_CAPACITY_WORKER_TIMEOUT_SECONDS"] == "${HERMES_CAPACITY_WORKER_TIMEOUT_SECONDS:-60}"
assert services["control-plane"]["environment"]["HERMES_VM_INVENTORY_WORKER_TIMEOUT_SECONDS"] == "${HERMES_VM_INVENTORY_WORKER_TIMEOUT_SECONDS:-60}"
assert services["node-agent"]["environment"]["HERMES_VM_INVENTORY_COLLECTION_ENABLED"] == "${HERMES_VM_INVENTORY_COLLECTION_ENABLED:-false}"
assert services["node-agent"]["environment"]["HERMES_VM_INVENTORY_REQUEST_TIMEOUT_SECONDS"] == "${HERMES_VM_INVENTORY_REQUEST_TIMEOUT_SECONDS:-20}"
assert services["node-agent"]["environment"]["HERMES_VM_INVENTORY_MAX_RESPONSE_BYTES"] == "${HERMES_VM_INVENTORY_MAX_RESPONSE_BYTES:-1048576}"
# Proxmox VM mutation runtime settings are disabled by default.
assert services["node-agent"]["environment"]["HERMES_PROXMOX_VM_RUNTIME_ENABLED"] == "${HERMES_PROXMOX_VM_RUNTIME_ENABLED:-false}"
assert services["node-agent"]["environment"]["HERMES_PROXMOX_VM_REQUEST_TIMEOUT_SECONDS"] == "${HERMES_PROXMOX_VM_REQUEST_TIMEOUT_SECONDS:-20}"
assert services["node-agent"]["environment"]["HERMES_PROXMOX_VM_MAX_RESPONSE_BYTES"] == "${HERMES_PROXMOX_VM_MAX_RESPONSE_BYTES:-1048576}"
assert services["node-agent"]["environment"]["HERMES_PROXMOX_VM_MAX_REQUEST_BODY_BYTES"] == "${HERMES_PROXMOX_VM_MAX_REQUEST_BODY_BYTES:-8192}"
assert services["node-agent"]["environment"]["HERMES_PROXMOX_VM_MAX_REQUESTS_PER_EXECUTION"] == "${HERMES_PROXMOX_VM_MAX_REQUESTS_PER_EXECUTION:-32}"
assert services["node-agent"]["environment"]["HERMES_PROXMOX_VM_TASK_POLL_ATTEMPTS"] == "${HERMES_PROXMOX_VM_TASK_POLL_ATTEMPTS:-30}"
assert services["node-agent"]["environment"]["HERMES_PROXMOX_VM_TASK_POLL_DELAY_SECONDS"] == "${HERMES_PROXMOX_VM_TASK_POLL_DELAY_SECONDS:-2}"
assert services["node-agent"]["environment"]["HERMES_PROXMOX_VM_VERIFY_ATTEMPTS"] == "${HERMES_PROXMOX_VM_VERIFY_ATTEMPTS:-5}"
assert services["node-agent"]["environment"]["HERMES_PROXMOX_VM_VERIFY_DELAY_SECONDS"] == "${HERMES_PROXMOX_VM_VERIFY_DELAY_SECONDS:-1}"
assert "HERMES_EXECUTION_HMAC_KEY" in services["node-agent"]["environment"]
assert "HERMES_PROVIDER_SSH_PROFILE_ROOT" in services["node-agent"]["environment"]
assert values["nodeAgent"]["enabled"] is False
assert values["nodeAgent"]["executionEnabled"] is False
assert values["nodeAgent"]["sshProfileSecret"] == ""
assert values["nodeAgent"]["infrastructureExecutionEnabled"] is False
assert values["nodeAgent"]["infrastructureCredentialSecret"] == ""
assert values["nodeAgent"]["infrastructureAllowHttp"] is False
assert values["nodeAgent"]["infrastructureIpmiTimeoutSeconds"] == 20
assert values["nodeAgent"]["infrastructureFirmwareVerifyAttempts"] == 60
assert values["nodeAgent"]["infrastructureFirmwareVerifyDelaySeconds"] == 5
assert values["nodeAgent"]["infrastructurePlatformVerifyAttempts"] == 90
assert values["nodeAgent"]["infrastructurePlatformVerifyDelaySeconds"] == 5
assert values["nodeAgent"]["capacityCollectionEnabled"] is False
assert values["nodeAgent"]["capacityRequestTimeoutSeconds"] == 20
assert values["nodeAgent"]["capacityMaxResponseBytes"] == 1048576
assert values["nodeAgent"]["capacityMaxRequests"] == 8
assert values["nodeAgent"]["capacityWorkerTimeoutSeconds"] == 60
assert values["nodeAgent"]["vmInventoryCollectionEnabled"] is False
assert values["nodeAgent"]["vmInventoryRequestTimeoutSeconds"] == 20
assert values["nodeAgent"]["vmInventoryMaxResponseBytes"] == 1048576
assert values["nodeAgent"]["vmInventoryWorkerTimeoutSeconds"] == 60
# Proxmox VM mutation runtime Helm values are disabled by default.
assert values["nodeAgent"]["proxmoxVmRuntimeEnabled"] is False
assert values["nodeAgent"]["proxmoxVmRequestTimeoutSeconds"] == 20
assert values["nodeAgent"]["proxmoxVmMaxResponseBytes"] == 1048576
assert values["nodeAgent"]["proxmoxVmMaxRequestBodyBytes"] == 8192
assert values["nodeAgent"]["proxmoxVmMaxRequestsPerExecution"] == 32
assert values["nodeAgent"]["proxmoxVmTaskPollAttempts"] == 30
assert values["nodeAgent"]["proxmoxVmTaskPollDelaySeconds"] == 2
assert values["nodeAgent"]["proxmoxVmVerifyAttempts"] == 5
assert values["nodeAgent"]["proxmoxVmVerifyDelaySeconds"] == 1
node_agent_template = (ROOT / "charts/hermes-control-plane/templates/node-agent.yaml").read_text()
for marker in ("runAsNonRoot: true", "runAsUser: 10022", "runAsGroup: 10022", "fsGroup: 10022", "defaultMode: 0440"):
    assert marker in node_agent_template, marker
for marker in (
    "HERMES_CAPACITY_COLLECTION_ENABLED", "HERMES_CAPACITY_REQUEST_TIMEOUT_SECONDS",
    "HERMES_CAPACITY_MAX_RESPONSE_BYTES", "HERMES_CAPACITY_MAX_REQUESTS",
):
    assert marker in node_agent_template, marker
for marker in (
    "HERMES_VM_INVENTORY_COLLECTION_ENABLED", "HERMES_VM_INVENTORY_REQUEST_TIMEOUT_SECONDS",
    "HERMES_VM_INVENTORY_MAX_RESPONSE_BYTES",
):
    assert marker in node_agent_template, marker
for marker in (
    "HERMES_PROXMOX_VM_RUNTIME_ENABLED", "HERMES_PROXMOX_VM_REQUEST_TIMEOUT_SECONDS",
    "HERMES_PROXMOX_VM_MAX_RESPONSE_BYTES", "HERMES_PROXMOX_VM_MAX_REQUEST_BODY_BYTES",
    "HERMES_PROXMOX_VM_MAX_REQUESTS_PER_EXECUTION", "HERMES_PROXMOX_VM_TASK_POLL_ATTEMPTS",
    "HERMES_PROXMOX_VM_TASK_POLL_DELAY_SECONDS", "HERMES_PROXMOX_VM_VERIFY_ATTEMPTS",
    "HERMES_PROXMOX_VM_VERIFY_DELAY_SECONDS",
):
    assert marker in node_agent_template, marker
control_plane_template = (ROOT / "charts/hermes-control-plane/templates/control-plane.yaml").read_text()
assert "HERMES_CAPACITY_WORKER_TIMEOUT_SECONDS" in control_plane_template
assert "HERMES_VM_INVENTORY_WORKER_TIMEOUT_SECONDS" in control_plane_template
for marker in (
    "HERMES_CAPACITY_COLLECTION_ENABLED=false", "HERMES_CAPACITY_REQUEST_TIMEOUT_SECONDS=20",
    "HERMES_CAPACITY_MAX_RESPONSE_BYTES=1048576", "HERMES_CAPACITY_MAX_REQUESTS=8",
    "HERMES_CAPACITY_WORKER_TIMEOUT_SECONDS=60",
    "HERMES_VM_INVENTORY_COLLECTION_ENABLED=false", "HERMES_VM_INVENTORY_REQUEST_TIMEOUT_SECONDS=20",
    "HERMES_VM_INVENTORY_MAX_RESPONSE_BYTES=1048576", "HERMES_VM_INVENTORY_WORKER_TIMEOUT_SECONDS=60",
    "HERMES_PROXMOX_VM_RUNTIME_ENABLED=false", "HERMES_PROXMOX_VM_REQUEST_TIMEOUT_SECONDS=20",
    "HERMES_PROXMOX_VM_MAX_RESPONSE_BYTES=1048576", "HERMES_PROXMOX_VM_MAX_REQUEST_BODY_BYTES=8192",
    "HERMES_PROXMOX_VM_MAX_REQUESTS_PER_EXECUTION=32", "HERMES_PROXMOX_VM_TASK_POLL_ATTEMPTS=30",
    "HERMES_PROXMOX_VM_TASK_POLL_DELAY_SECONDS=2", "HERMES_PROXMOX_VM_VERIFY_ATTEMPTS=5",
    "HERMES_PROXMOX_VM_VERIFY_DELAY_SECONDS=1",
):
    assert marker in (ROOT / ".env.example").read_text(), marker
compose_text = (ROOT / "docker-compose.yml").read_text()
for marker in (
    "HERMES_VM_INVENTORY_COLLECTION_ENABLED", "HERMES_VM_INVENTORY_REQUEST_TIMEOUT_SECONDS",
    "HERMES_VM_INVENTORY_MAX_RESPONSE_BYTES", "HERMES_VM_INVENTORY_WORKER_TIMEOUT_SECONDS",
    "HERMES_PROXMOX_VM_RUNTIME_ENABLED", "HERMES_PROXMOX_VM_REQUEST_TIMEOUT_SECONDS",
    "HERMES_PROXMOX_VM_MAX_RESPONSE_BYTES", "HERMES_PROXMOX_VM_MAX_REQUEST_BODY_BYTES",
    "HERMES_PROXMOX_VM_MAX_REQUESTS_PER_EXECUTION", "HERMES_PROXMOX_VM_TASK_POLL_ATTEMPTS",
    "HERMES_PROXMOX_VM_TASK_POLL_DELAY_SECONDS", "HERMES_PROXMOX_VM_VERIFY_ATTEMPTS",
    "HERMES_PROXMOX_VM_VERIFY_DELAY_SECONDS",
):
    assert marker in compose_text, marker
values_text = (ROOT / "charts/hermes-control-plane/values.yaml").read_text()
for marker in (
    "vmInventoryCollectionEnabled: false", "vmInventoryRequestTimeoutSeconds: 20",
    "vmInventoryMaxResponseBytes: 1048576", "vmInventoryWorkerTimeoutSeconds: 60",
    "proxmoxVmRuntimeEnabled: false", "proxmoxVmRequestTimeoutSeconds: 20",
    "proxmoxVmMaxResponseBytes: 1048576", "proxmoxVmMaxRequestBodyBytes: 8192",
    "proxmoxVmMaxRequestsPerExecution: 32", "proxmoxVmTaskPollAttempts: 30",
    "proxmoxVmTaskPollDelaySeconds: 2", "proxmoxVmVerifyAttempts: 5",
    "proxmoxVmVerifyDelaySeconds: 1",
):
    assert marker in values_text, marker
validate_script = (ROOT / "validate.sh").read_text()
assert 'PYTHONPATH=node-agent/src "$PYTHON_BIN" -m pytest -q node-agent/tests' in validate_script
assert 'HERMES_PROVIDER_EXECUTION_ENABLED:-false' in (ROOT / "docker-compose.yml").read_text()
assert 'HERMES_CAPACITY_COLLECTION_ENABLED=false' in (ROOT / ".env.example").read_text()
assert 'capacityCollectionEnabled: false' in (ROOT / "charts/hermes-control-plane/values.yaml").read_text()
assert 'executionEnabled: false' in (ROOT / "charts/hermes-control-plane/values.yaml").read_text()
assert 'infrastructureExecutionEnabled: false' in (ROOT / "charts/hermes-control-plane/values.yaml").read_text()
assert (ROOT / "node-agent/src/hermes_node_agent/infrastructure_runtime.py").is_file()
assert (ROOT / "node-agent/src/hermes_node_agent/capacity_runtime.py").is_file()
assert (ROOT / "node-agent/tests/test_capacity_runtime.py").is_file()
assert (ROOT / "control-plane/tests/test_dev5_capacity_refresh.py").is_file()
# VM inventory collector files are present.
assert (ROOT / "node-agent/src/hermes_node_agent/vm_inventory_runtime.py").is_file()
assert (ROOT / "node-agent/tests/test_vm_inventory_runtime.py").is_file()
assert (ROOT / "control-plane/tests/test_dev5_vm_inventory_refresh.py").is_file()
# Proxmox VM mutation runtime module, tests, and operator runbook are present.
assert (ROOT / "node-agent/src/hermes_node_agent/proxmox_runtime.py").is_file()
assert (ROOT / "node-agent/tests/test_proxmox_runtime.py").is_file()
proxmox_runbook = (ROOT / "docs/PROXMOX-VM-RUNTIME-VALIDATION.md").read_text()
for marker in (
    "HERMES_INFRASTRUCTURE_EXECUTION_ENABLED=true",
    "HERMES_PROXMOX_VM_RUNTIME_ENABLED=true",
    "vm.create", "vm.clone", "vm.update", "vm.delete", "vm.power", "network.attach", "snapshot.create", "snapshot.restore",
    "Drift rejection", "Replay rejection", "Redaction", "exact pushed candidate SHA",
):
    assert marker in proxmox_runbook, marker
node_agent_dockerfile = (ROOT / "node-agent/Dockerfile").read_text()
assert "openssh-client ca-certificates ipmitool" in node_agent_dockerfile
node_agent_main = (ROOT / "node-agent/src/hermes_node_agent/main.py").read_text()
assert "ipmi-lanplus-runtime" in node_agent_main
assert "pxe-unattended-runtime" in node_agent_main
assert (ROOT / "control-plane/tests/test_dev5_batch_c9_switch_network_runtime.py").is_file()
assert (ROOT / "node-agent/tests/test_network_switch_runtime.py").is_file()
assert (ROOT / "node-agent/requirements-dev.txt").is_file()
assert 'Test Node Agent' in validate_workflow
assert (ROOT / "node-agent/tests/test_pxe_runtime.py").is_file()
assert (ROOT / "control-plane/tests/test_dev5_batch_c_infrastructure_runtime.py").is_file()
assert (ROOT / "control-plane/tests/test_dev5_batch_c5b_pxe_runtime.py").is_file()
assert (ROOT / "control-plane/tests/test_dev5_batch_c6_storage_runtime.py").is_file()
assert (ROOT / "node-agent/tests/test_redfish_storage_runtime.py").is_file()

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
LOCAL_ONLY_ROOT_FILES = {".env", ".env.sandbox", ".coverage"}


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
    # Wizard-generated secret backups (existing .env backup, sandbox env + its backup).
    if rel.as_posix().startswith(".env.backup-") or rel.as_posix().startswith(".env.sandbox."):
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

print("0.5.11-config-static: PASS")
