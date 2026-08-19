from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]


def text(path: str) -> str:
    return (ROOT / path).read_text()


assert text("VERSION").strip() == "0.5.11-dev.3"
assert 'appVersion: "0.5.11-dev.3"' in text("charts/hermes-control-plane/Chart.yaml")

# Frozen dev.2 trust boundary remains present.
cred_main = text("credential-service/src/hermes_credential_service/main.py")
assert "Fernet" in cred_main
assert "raw secret material is forbidden" in cred_main
assert re.search(r'@app\.get\("/v1/credentials/\{credential_id\}"\)', cred_main)

cp_main = text("control-plane/src/hermes_control_plane/main.py")
models = text("control-plane/src/hermes_control_plane/models.py")
factory = text("control-plane/src/hermes_control_plane/cluster_factory.py")
providers = text("control-plane/src/hermes_control_plane/providers.py")

for marker in (
    "ClusterBlueprintCreate", "ClusterProfileCreate", "ClusterCreate", "NodeRoleCreate",
    "ProvisioningRunCreate", "AddonPlanCreate", "UpgradePlanCreate", "BackupPlanCreate",
    'operation="cluster.provision.apply"', 'operation="cluster.addons.apply"',
    'operation="cluster.upgrade"', 'operation="cluster.backup.apply"',
    '"radar_contract"', '"hubble_contract"',
):
    assert marker in cp_main or marker in models, marker

# Provider execution specs are deterministic data contracts, not generated shell/script surfaces.
for marker in ("KubesprayExecutionSpec", "K3sExecutionSpec", "RKE2ExecutionSpec", '"arbitrary_install_script": False'):
    assert marker in factory, marker
assert "subprocess" not in factory
assert "os.system" not in factory
assert "curl | sh" not in factory
assert "kubectl-aban-plugin" not in factory

# Provider and add-on writes require explicit versions and remain ChangeSet-bound.
assert "provider_version" in models and "addon_versions" in models
assert "provider_version" in factory and '"provider_version_pin": "required"' in providers
assert "explicit version pins required for add-ons" in factory
assert factory.count('"version_pin_required": True') >= 8
assert "OPERATIONAL_PROFILES" in factory
for profile in ("lab-minimal", "lab-full", "production", "production-ha", "production-hardened"):
    assert f'"{profile}"' in factory
assert "changeset-exact-hash-approval" in factory

# Radar/Hubble remain first-class but cannot bypass governance or leak raw flow payloads to AI/UI.
assert providers.count('"governance_bypass": False') >= 2
assert '"redaction": "required-before-ai-ui"' in providers
assert '"aggregation": "required-before-ai-ui"' in providers
assert '"raw-payloads"' in factory
assert '"unredacted-l7-bodies"' in factory
assert "HubbleFlowSummaryCreate" in models
assert "raw_payload" not in models.lower()

# No local production image publishing path may appear in push.sh.
push = text("push.sh").lower()
for forbidden in ("docker push", "docker buildx", "build-push-action", "ghcr.io"):
    assert forbidden not in push, forbidden
assert "git push" in push
assert "a71b03a54ed2f619d3605c0c08d46de35ad5911c" in push
assert "v0.5.11-dev.3" in push
assert "pr ready" not in push

workflow = text(".github/workflows/publish-images.yml")
assert "secrets.DOCKERHUB_USERNAME" in workflow
assert "secrets.DOCKERHUB_TOKEN" in workflow
assert "ghcr.io" not in workflow.lower()
assert "linux/amd64,linux/arm64" in workflow

print("0.5.11-dev.3-source-security: PASS")
