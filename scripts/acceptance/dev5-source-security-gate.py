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
unified_verification = text("control-plane/src/hermes_control_plane/verification.py")
artifact_mirror = text("control-plane/src/hermes_control_plane/artifact_mirror.py")
operator_center = text("control-plane/src/hermes_control_plane/operator_center.py")
ui = text("control-plane/src/hermes_control_plane/static/index.html")
tickets = text("control-plane/src/hermes_control_plane/tickets.py")
radar = text("control-plane/src/hermes_control_plane/radar.py")
hubble = text("kubernetes-broker/src/hermes_kubernetes_broker/hubble.py")
diagnostics = text("kubernetes-broker/src/hermes_kubernetes_broker/diagnostics.py")
kube_broker = text("kubernetes-broker/src/hermes_kubernetes_broker/main.py")

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

# Dev.5 Hubble runtime is broker-owned, bounded, scoped, redacted and never returns raw L7 bodies.
for marker in (
    'class HubbleLiveQuery',
    '@app.post("/v1/clusters/{cluster_id}/network/live")',
    '@app.get("/v1/clusters/{cluster_id}/network/history")',
    '@app.get("/v1/clusters/{cluster_id}/network/live/stream")',
    'kubernetes_broker.post(',
    '"/v1/hubble/collect"',
    'raw_flow_bodies_returned',
):
    assert marker in models or marker in cp_main, marker
assert '@app.post("/v1/hubble/collect")' in kube_broker
assert 'subprocess.run(args' in hubble
assert '"--port-forward"' in hubble and '"jsonpb"' in hubble
assert 'MAX_EVENTS = 200' in hubble
assert 'namespace_allowlist' in hubble and 'namespace_denylist' in hubble
for forbidden in ('"url":', '"headers":', '"body":', 'shell=True', 'os.system'):
    assert forbidden not in hubble, forbidden
assert 'raw_flow_bodies_returned": False' in hubble
assert 'LIMIT 2000' in cp_main

# Dev.5 native diagnostics are executable only through fixed read-only broker collectors.
for marker in (
    'class KubernetesDiagnosticsQuery',
    'class KubernetesDiagnosticsBrokerResult',
    '@app.post("/v1/clusters/{cluster_id}/diagnostics/run")',
    'KubernetesDiagnosticsBrokerResult.model_validate',
    'kubernetes.diagnostics.executed',
    'DIAGNOSTIC_FORBIDDEN_EVIDENCE_KEYS',
):
    assert marker in models or marker in cp_main, marker
for marker in (
    '@app.post("/v1/diagnostics/run")',
    '_diagnostic_scoped_list',
    '_diagnostic_metrics',
    'diagnostics_provider.evaluate',
):
    assert marker in kube_broker, marker
for check_id in (
    'nodes.health', 'pods.health', 'workloads.health', 'pods.oom', 'resources.cpu-memory',
    'storage.health', 'events.correlation', 'network.cilium', 'network.hubble', 'network.dns',
    'network.ingress', 'network.networkpolicy', 'security.rbac', 'security.privileged',
    'security.capabilities', 'security.hostpath', 'security.exposed-services',
    'security.ingress-tls', 'security.webhooks', 'gitops.argocd', 'rollout.health',
):
    assert f'"{check_id}"' in diagnostics, check_id
assert '"secret_data_requested": False' in diagnostics
assert '"mutation_commands_executed": False' in diagnostics
assert 'raw_flow_bodies_returned' in diagnostics
for forbidden in ('subprocess', 'os.system', 'shell=True', 'kubectl exec', 'kubectl logs', 'kubectl apply', 'kubectl delete', 'kubectl patch', 'kubectl create'):
    assert forbidden not in diagnostics, forbidden
assert '"kubectl", "get"' in kube_broker
assert 'unsupported diagnostic checks' in kube_broker
assert 'cluster_read target scope required' in kube_broker

# Dev.5 Operator Center closes UI navigation without upgrading unfinished runtime providers.
assert '@app.get("/v1/operator-center/contracts")' in cp_main
assert '"operator-center-ui"' in cp_main
assert '"ui_state": UI_STATE' in operator_center
assert '"runtime_state_is_separate_from_ui_state": True' in operator_center
assert '"credential_material_rendered": False' in operator_center
assert '"mutation_ui": "observe-plan-inspect-only"' in operator_center
for surface_id in (
    "kubernetes.network-live", "kubernetes.security", "kubernetes.rbac",
    "cluster-factory.bare-metal", "infrastructure.vmware", "infrastructure.openstack",
    "infrastructure.aws", "infrastructure.azure", "infrastructure.gcp",
    "governance.artifact-mirror",
):
    assert f'"{surface_id}"' in operator_center, surface_id
for contract_only in (
    "cluster-factory.bare-metal", "infrastructure.vmware", "infrastructure.openstack",
    "infrastructure.aws", "infrastructure.azure", "infrastructure.gcp",
):
    fragment = operator_center.split(f'"{contract_only}"', 1)[1].split("),", 1)[0]
    assert '"CONTRACT_ONLY"' in fragment, contract_only
for partial_surface in ("cluster-factory.images-artifacts", "governance.artifact-mirror"):
    fragment = operator_center.split(f'"{partial_surface}"', 1)[1].split("),", 1)[0]
    assert '"PARTIAL"' in fragment, partial_surface
assert 'Operator Center' in ui and '/v1/operator-center/contracts' in ui
operator_section = ui.split('<section id="operator-center"', 1)[1].split('</section>', 1)[0]
for forbidden in ("approveChange", "executeChange", "createChange", "kubectl", "helm upgrade"):
    assert forbidden not in operator_section, forbidden

# Dev.5 trusted Kubernetes day-2 execution is exact-preview-bound and actively verified.
for marker in (
    'KUBERNETES_DAY2_RUNTIME_OPERATIONS',
    'validate_kubernetes_day2_parameters',
    '"kubernetes_day2_runtime": KUBERNETES_DAY2_RUNTIME_OPERATIONS',
):
    assert marker in operations, marker
for marker in (
    '@app.post("/v1/operation-jobs/{job_id}/execute")',
    'job["executor"] not in {"kubernetes-broker", "artifact-mirror-worker"}',
    '"/v1/day2/preview"',
    '"/v1/day2/execute"',
    'verification.runtime_recorded',
    'operation_job.runtime_completed',
):
    assert marker in cp_main, marker
for marker in (
    '@app.post("/v1/day2/preview")',
    '@app.post("/v1/day2/execute")',
    '_assert_day2_runtime_preconditions',
    'node state changed after preview',
    'workload state changed after preview',
    'Helm release changed after preview',
    '--dry-run=server',
    '--hide-secret',
):
    assert marker in kube_broker, marker
for operation in (
    'cluster.node.cordon', 'cluster.node.uncordon', 'cluster.node.drain',
    'cluster.workload.restart', 'cluster.workload.scale',
    'cluster.addon.install', 'cluster.addon.upgrade', 'cluster.helm.apply',
    'cluster.gitops.sync', 'cluster.cilium.upgrade',
):
    assert f'"{operation}"' in kube_broker, operation
for forbidden in ('shell=True', 'os.system', 'kubectl exec', 'kubectl cp'):
    assert forbidden not in kube_broker, forbidden
assert 'mutation_gate") != "changeset-exact-hash-approval"' in kube_broker
assert 'raw_credentials_returned' in kube_broker
for marker in (
    'applications.argoproj.io',
    'GitOps sync requires a full 40- or 64-character commit digest',
    'Argo CD Application state changed after preview',
    '--for=jsonpath={.status.sync.status}=Synced',
    'Cilium upgrade must target release cilium in kube-system with a Cilium chart',
    'hubble_provider.collect',
    'cilium-ready',
    'hubble-ready',
):
    assert marker in kube_broker, marker

# Dev.5 active unified verification executes real read probes and never upgrades missing provider evidence to success.
for marker in (
    'class UnifiedVerificationQuery',
    '@app.post("/v1/clusters/{cluster_id}/verify", status_code=201)',
    'verification.active.executed',
    'unsupported_probes_report_skip',
    'unified_verification.overall_status',
):
    assert marker in models or marker in cp_main, marker
for check_id in (
    'networking', 'api-server', 'nodes', 'cilium', 'hubble', 'dns', 'storage',
    'ingress-tls', 'gitops', 'observability', 'radar', 'hermes-agent', 'baseline-security',
):
    assert f'"{check_id}"' in unified_verification or f'"{check_id}"' in operations, check_id
for honest_skip in ('Active host/SSH verification requires', 'Direct etcd quorum verification', 'Hermes Agent verification requires'):
    assert honest_skip in unified_verification, honest_skip
assert 'prometheus_probe' in unified_verification
assert 'not-configured' in unified_verification
for forbidden in ('subprocess', 'os.system', 'shell=True', 'kubectl ', 'helm '):
    assert forbidden not in unified_verification, forbidden
assert 'radar_provider.health' in cp_main
assert 'credential_material_returned' in cp_main

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


# Dev.5 artifact mirror has a real constrained blob-sync runtime without pretending registry protocols are complete.
for marker in (
    'ARTIFACT_RUNTIME_SOURCE_SCHEMES = {"file", "https"}',
    'ARTIFACT_RUNTIME_DESTINATION_SCHEMES = {"file"}',
    'validate_artifact_mirror_parameters',
    'artifact_mirror_runtime_capable',
    '"artifact-mirror-contract"',
):
    assert marker in operations or marker in cp_main, marker
for marker in (
    'class _NoRedirect',
    'HERMES_ARTIFACT_HTTPS_HOST_ALLOWLIST',
    'HERMES_ARTIFACT_MIRROR_MAX_BYTES',
    'HERMES_ARTIFACT_MIRROR_TIMEOUT_SECONDS',
    'artifact HTTPS source host is not allowlisted',
    'artifact source redirects are forbidden',
    'os.replace(temp_path, destination_path)',
    'source-digest',
    'destination-digest',
    'ALREADY_MIRRORED',
    'raw_credentials_returned',
):
    assert marker in artifact_mirror, marker
for forbidden in ('subprocess', 'os.system', 'shell=True', 'eval(', 'exec('):
    assert forbidden not in artifact_mirror, forbidden
assert 'artifact-mirror-worker' in cp_main
assert 'source=executor' in cp_main
assert 'sync_state' in cp_main

print("0.5.11-dev.5-source-security: PASS")
