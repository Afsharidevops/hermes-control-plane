from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]


def text(path: str) -> str:
    return (ROOT / path).read_text()


assert text("VERSION").strip() == "0.5.11-dev.5"
assert 'appVersion: "0.5.11-dev.5"' in text("charts/hermes-control-plane/Chart.yaml")

# Frozen trust/security foundations remain present.
cred_main = text("credential-service/src/hermes_credential_service/main.py")
assert "Fernet" in cred_main
assert "raw secret material is forbidden" in cred_main
assert re.search(r'@app\.get\("/v1/credentials/\{credential_id\}"\)', cred_main)

cp_main = text("control-plane/src/hermes_control_plane/main.py")
models = text("control-plane/src/hermes_control_plane/models.py")
factory = text("control-plane/src/hermes_control_plane/cluster_factory.py")
providers = text("control-plane/src/hermes_control_plane/providers.py")
operations = text("control-plane/src/hermes_control_plane/operations.py")
tickets = text("control-plane/src/hermes_control_plane/tickets.py")
radar = text("control-plane/src/hermes_control_plane/radar.py")

# Frozen dev.3/dev.4 contracts remain intact while dev.5 adds real runtime surfaces.
for marker in (
    "ClusterBlueprintCreate", "ClusterProfileCreate", "ClusterCreate", "NodeRoleCreate",
    "ProvisioningRunCreate", "AddonPlanCreate", "UpgradePlanCreate", "BackupPlanCreate",
    'operation="cluster.provision.apply"', 'operation="cluster.addons.apply"',
    'operation="cluster.upgrade"', 'operation="cluster.backup.apply"',
    "KubesprayExecutionSpec", "K3sExecutionSpec", "RKE2ExecutionSpec",
    "InfrastructureProviderCreate", "OperationsIntentPlanCreate", "ArtifactMirrorItemCreate",
    "VerificationResultCreate", "OperationJobTransition",
):
    assert marker in cp_main or marker in models or marker in factory, marker
assert providers.count('"governance_bypass": False') >= 2
assert '"redaction": "required-before-ai-ui"' in providers
assert '"aggregation": "required-before-ai-ui"' in providers

# Existing mutation governance remains exact-hash, policy, approval and target-drift bound.
assert "operation job exact plan hash no longer matches ChangeSet" in cp_main
assert "operation plan is not exactly bound to the ChangeSet plan" in cp_main
assert "valid distinct integrity-checked approval(s) required" in cp_main
assert "target drift detected" in cp_main
assert "_require_current_policy_generation" in cp_main
assert "_approval_is_valid" in cp_main
assert "status='CONSUMED'" in cp_main
assert "verify_ticket(" in tickets
assert "invalid execution ticket signature" in tickets
assert "execution ticket does not match the authorized operation job" in cp_main

# Dev.5 Radar runtime is read-only and typed at the Hermes boundary.
assert '"radar"' in models.split("IntegrationKind =", 1)[1].split("\n", 1)[0]
for marker in (
    "ContextMode = Literal[\"AUTO\", \"RADAR\", \"NATIVE\"]",
    "class RadarIntelligenceQuery",
    '@app.post("/v1/clusters/{cluster_id}/intelligence/query")',
    "radar_provider.validate_read_tool",
    "_configured_radar_integration",
    "_query_native_intelligence",
):
    assert marker in models or marker in cp_main, marker
for read_tool in ("get_dashboard", "issues", "list_resources", "search", "get_resource", "get_topology", "get_neighborhood"):
    assert f'"{read_tool}"' in radar, read_tool
for write_tool in ("apply_resource", "patch_resource", "restart", "scale", "rollback", "cordon", "drain", "manage_gitops"):
    assert f'"{write_tool}"' not in radar.split("READ_TOOLS =", 1)[1].split("}", 1)[0], write_tool
assert "unsupported Radar arguments" in radar
assert "Radar tool is not allowlisted for read-only Hermes use" in radar
assert "embedded credentials" in radar
assert "authenticated Radar credential delivery must use a provider worker" in cp_main
assert "Radar integration belongs to a different environment" in cp_main
assert "native Kubernetes target belongs to a different environment" in cp_main
assert 'payload.mode != "NATIVE"' in cp_main
assert 'payload.mode == "RADAR"' in cp_main

# Defense-in-depth provider redaction: no Secret body or direct workload env values reach UI/AI.
assert 'kind == "secret"' in radar
assert 'normalized == "env"' in radar
assert 'entry["value"] = "[REDACTED]"' in radar
assert "MAX_RESPONSE_BYTES" in radar
assert "Mcp-Session-Id" in radar
assert '"tools/call"' in radar

# Native fallback remains behind the existing constrained Kubernetes Broker.
assert 'kubernetes_broker.post("/v1/discover"' in cp_main
assert '"secret_data_requested": False' in text("kubernetes-broker/src/hermes_kubernetes_broker/main.py")

# Generic typed provider contracts retain their credential boundary and no arbitrary command generation.
for forbidden in ("subprocess", "os.system", "shell=True", "curl | sh"):
    assert forbidden not in operations, forbidden
assert '"arbitrary_cli": False' in operations
assert '"arbitrary_install_script": False' in operations
assert '"arbitrary_shell": False' in operations
assert "credential-service-provider-worker-only" in operations

# Guarded release scripts are forward-only from the exact frozen dev.4 boundary.
apply = text("apply.sh")
push = text("push.sh")
for raw in (apply, push):
    assert "d4eb9b7ab2564301c09b8c0d36a2e9d53b843273" in raw
    assert "v0.5.11-dev.4" in raw
    assert "git merge-base --is-ancestor" in raw
assert "v0.5.11-dev.5" in push
assert "branch-ci-green-sha" in push
assert "git tag -a" in push and "git tag -f" not in push
assert "pr ready" not in push.lower()
for forbidden in ("docker push", "docker buildx", "build-push-action", "ghcr.io"):
    assert forbidden not in push.lower(), forbidden

workflow = text(".github/workflows/publish-images.yml")
assert "secrets.DOCKERHUB_USERNAME" in workflow
assert "secrets.DOCKERHUB_TOKEN" in workflow
assert "ghcr.io" not in workflow.lower()
assert "linux/amd64,linux/arm64" in workflow

print("0.5.11-dev.5-source-security: PASS")
