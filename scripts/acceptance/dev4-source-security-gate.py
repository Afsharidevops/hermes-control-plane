from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]


def text(path: str) -> str:
    return (ROOT / path).read_text()


assert text("VERSION").strip() == "0.5.11-dev.4"
assert 'appVersion: "0.5.11-dev.4"' in text("charts/hermes-control-plane/Chart.yaml")

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

# Dev.3 Cluster Factory remains intact.
for marker in (
    "ClusterBlueprintCreate", "ClusterProfileCreate", "ClusterCreate", "NodeRoleCreate",
    "ProvisioningRunCreate", "AddonPlanCreate", "UpgradePlanCreate", "BackupPlanCreate",
    'operation="cluster.provision.apply"', 'operation="cluster.addons.apply"',
    'operation="cluster.upgrade"', 'operation="cluster.backup.apply"',
    "KubesprayExecutionSpec", "K3sExecutionSpec", "RKE2ExecutionSpec",
):
    assert marker in cp_main or marker in models or marker in factory, marker
assert providers.count('"governance_bypass": False') >= 2
assert '"redaction": "required-before-ai-ui"' in providers
assert '"aggregation": "required-before-ai-ui"' in providers

# Dev.4 shared Operations Center contract and mutation surfaces.
for marker in (
    "InfrastructureProviderCreate", "OperationsIntentPlanCreate", "ArtifactMirrorItemCreate",
    "VerificationResultCreate", "OperationJobTransition",
    '@app.get("/v1/operations-center/contracts")',
    '@app.post("/v1/operations-center/intents/plan"',
    '@app.post("/v1/operation-jobs/{job_id}/authorize")',
    '@app.post("/v1/verifications"',
):
    assert marker in cp_main or marker in models, marker

for provider in ("vmware", "openstack", "aws", "azure", "gcp"):
    assert f'"{provider}"' in operations, provider
for provider in ("redfish", "ipmi", "pxe", "network-switch"):
    assert f'"{provider}"' in operations, provider
for operation in (
    "cluster.worker.add", "cluster.worker.remove", "cluster.worker.replace",
    "cluster.node.cordon", "cluster.node.drain", "cluster.workload.restart",
    "cluster.addon.upgrade", "cluster.helm.apply", "cluster.gitops.sync",
    "cluster.kubernetes.upgrade", "cluster.cilium.upgrade", "cluster.etcd.snapshot",
    "cluster.restore", "cluster.certificate.rotate", "cluster.node.maintenance",
    "cluster.decommission", "cluster.infrastructure.scale", "cluster.template.clone",
    "cluster.disaster-recovery",
):
    assert f'"{operation}"' in operations, operation

# Typed providers only: no generated command execution in planner contracts.
for forbidden in ("subprocess", "os.system", "shell=True", "curl | sh"):
    assert forbidden not in operations, forbidden
assert '"arbitrary_cli": False' in operations
assert '"arbitrary_install_script": False' in operations
assert '"arbitrary_shell": False' in operations
assert "changeset-exact-hash-approval" in operations
assert "reject-on-snapshot-change" in operations
assert "credential-service-provider-worker-only" in operations

# Target drift, integrity-checked approvals, exact typed-plan binding and constrained signed tickets
# remain enforced before a generic provider/broker/agent job can enter execution.
assert "operation job exact plan hash no longer matches ChangeSet" in cp_main
assert "operation plan is not exactly bound to the ChangeSet plan" in cp_main
assert "valid distinct integrity-checked approval(s) required" in cp_main
assert "target drift detected" in cp_main
assert "_require_current_policy_generation" in cp_main
assert "_approval_is_valid" in cp_main
assert "status='CONSUMED'" in cp_main
assert "execution_ticket" in models
assert "verify_ticket(" in tickets
assert "invalid execution ticket signature" in tickets
assert "execution ticket does not match the authorized operation job" in cp_main
assert "_validate_credential_metadata(payload.desired_state)" in cp_main
assert "_reject_embedded_url_credentials" in cp_main
for secret_marker in ("api_key", "client_secret", "user_data", "cloud_init"):
    assert f'"{secret_marker}"' in cp_main

# Air-gap plans are version/digest pinned and verified on both sides.
assert r'^sha256:[0-9a-f]{64}$' in models
assert "verify-source-digest" in operations
assert "verify-destination-digest" in operations

# Handoff application verifies the package checksum manifest before touching a real Git checkout.
apply = text("apply.sh")
assert "sha256sum --quiet -c MANIFEST.sha256" in apply
assert "git merge-base --is-ancestor" in apply

# Local push remains source/tag-only and cannot tag before branch CI is bound to HEAD.
push = text("push.sh")
for forbidden in ("docker push", "docker buildx", "build-push-action", "ghcr.io"):
    assert forbidden not in push.lower(), forbidden
assert "8547c44de4f6e8116d70f2690b50a50c895eba34" in push
assert "v0.5.11-dev.3" in push
assert "v0.5.11-dev.4" in push
assert "branch-ci-green-sha" in push
assert "BRANCH_CI_GREEN_SHA" in push
assert "git tag -a" in push and "git tag -f" not in push
assert "pr ready" not in push.lower()

workflow = text(".github/workflows/publish-images.yml")
assert "secrets.DOCKERHUB_USERNAME" in workflow
assert "secrets.DOCKERHUB_TOKEN" in workflow
assert "ghcr.io" not in workflow.lower()
assert "linux/amd64,linux/arm64" in workflow

print("0.5.11-dev.4-source-security: PASS")
