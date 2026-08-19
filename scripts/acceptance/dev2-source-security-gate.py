from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]

def text(path: str) -> str:
    return (ROOT / path).read_text()

assert text("VERSION").strip() == "0.5.11-dev.2"
assert 'appVersion: "0.5.11-dev.2"' in text("charts/hermes-control-plane/Chart.yaml")

workflow = text(".github/workflows/publish-images.yml")
assert "hermes-control-plane-credential-service" in workflow
assert "context: ./credential-service" in workflow
assert "secrets.DOCKERHUB_USERNAME" in workflow
assert "secrets.DOCKERHUB_TOKEN" in workflow
assert "vars.DOCKERHUB_USERNAME" not in workflow
assert "ghcr.io" not in workflow.lower()
assert "linux/amd64,linux/arm64" in workflow

push = text("push.sh")
for forbidden in ("docker push", "buildx", "push-images.sh", "ghcr.io"):
    assert forbidden not in push.lower(), f"push.sh contains forbidden image-publish path: {forbidden}"
assert "git push" in push
assert "dev/0.5.11" in push
assert "1764cad667717ec78156af8f9f3fcc30eb84c1f5" in push
assert "pr ready" not in push.lower()

compose = text("docker-compose.yml")
assert "credential-service:" in compose
assert "credential-net:" in compose
assert "internal: true" in compose
assert "HERMES_CREDENTIAL_MASTER_KEY" in compose
smart_router_block = compose.split("  smart-router:", 1)[1].split("\n  kubernetes-broker:", 1)[0]
assert "HERMES_CREDENTIAL_MASTER_KEY" not in smart_router_block
hermes_block = compose.split("  hermes:", 1)[1].split("\n  node-agent:", 1)[0]
assert "HERMES_CREDENTIAL_MASTER_KEY" not in hermes_block

cred_main = text("credential-service/src/hermes_credential_service/main.py")
assert "ciphertext" in cred_main
assert "Fernet" in cred_main
assert "credential.revoked" in cred_main
assert "credential.updated" in cred_main
assert '@app.patch("/v1/credentials/{credential_id}")' in cred_main
assert "raw secret material is forbidden" in cred_main
assert re.search(r'@app\.get\("/v1/credentials/\{credential_id\}"\)', cred_main)
assert "return _redacted(row)" in cred_main
assert "secret_material" not in "\n".join(line for line in cred_main.splitlines() if line.lstrip().startswith("return "))

cp_main = text("control-plane/src/hermes_control_plane/main.py")
for marker in (
    '"server-registry"', '"ssh-preflight"', '"bootstrap-jobs"',
    '"radar-provider-foundation"', '"hubble-provider-foundation"',
    '"radar.apply"', '"hubble.flows"', '"bootstrap.apply"',
    'mutation_policy',
):
    assert marker in cp_main or marker in text("control-plane/src/hermes_control_plane/providers.py"), marker
assert 'INFRA_MUTATION_ADAPTERS = {"kubernetes", "helm", "ssh", "bootstrap", "radar", "hubble", "provider"}' in cp_main
assert "server must have PASS preflight status before bootstrap planning" in cp_main
assert "provider job requires ChangeSet state" in cp_main
assert "server SSH credential is not active/configured" in cp_main
assert '@app.get("/v1/provider-jobs/{job_id}/stream")' in cp_main
assert '@app.post("/v1/provider-jobs/{job_id}/retry")' in cp_main
assert '@app.post("/v1/provider-jobs/{job_id}/resume")' in cp_main
assert 'StreamingResponse' in cp_main

providers = text("control-plane/src/hermes_control_plane/providers.py")
assert '"radar"' in providers and '"hubble"' in providers
assert providers.count('"governance_bypass": False') >= 2
assert '"redaction": "required-before-ai-ui"' in providers

preflight = text("control-plane/src/hermes_control_plane/preflight.py")
assert "fixed product code, not model-generated shell" in preflight
assert "StrictHostKeyChecking" not in preflight  # transport/profile layer owns SSH options
assert "curl | sh" not in preflight

print("0.5.11-dev.2-source-security: PASS")
