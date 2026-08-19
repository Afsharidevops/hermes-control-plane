from __future__ import annotations

from pathlib import Path
import re
import yaml

ROOT = Path(__file__).resolve().parents[2]


def load_yaml(path: str):
    text = (ROOT / path).read_text()
    # compose() is intentionally used for GitHub workflow syntax too, because YAML 1.1
    # loaders may coerce the key `on` to a boolean even though GitHub treats it as text.
    yaml.compose(text)
    return yaml.safe_load(text)

compose = load_yaml("docker-compose.yml")
assert isinstance(compose, dict) and isinstance(compose.get("services"), dict)
services = compose["services"]
for required in (
    "control-plane", "credential-service", "router-gateway", "smart-router",
    "kubernetes-broker", "hermes", "node-agent",
):
    assert required in services, required

networks = compose.get("networks") or {}
assert networks.get("credential-net", {}).get("internal") is True
cred = services["credential-service"]
assert "credential-net" in (cred.get("networks") or [])
for llm_service in ("smart-router", "hermes", "router-gateway"):
    serialized = yaml.safe_dump(services[llm_service])
    assert "HERMES_CREDENTIAL_MASTER_KEY" not in serialized

chart = load_yaml("charts/hermes-control-plane/Chart.yaml")
values = load_yaml("charts/hermes-control-plane/values.yaml")
assert chart["version"] == "0.5.11-dev.2"
assert str(chart["appVersion"]) == "0.5.11-dev.2"
assert str(values["imageTag"]) == "0.5.11-dev.2"
assert values["credentialService"]["enabled"] is True
cred_chart = (ROOT / "charts/hermes-control-plane/templates/credential-service.yaml").read_text()
for marker in (
    "hermes-control-plane-credential-service",
    "HERMES_CREDENTIAL_ADMIN_TOKEN",
    "HERMES_CREDENTIAL_SERVICE_TOKEN",
    "HERMES_CREDENTIAL_MASTER_KEY",
    "HERMES_CONTROL_PLANE_URL",
):
    assert marker in cred_chart, marker
for pod_template in (
    "control-plane.yaml", "hermes-agent.yaml", "kubernetes-broker.yaml",
    "nine-router.yaml", "node-agent.yaml", "omniroute.yaml",
    "router-gateway.yaml", "smart-router.yaml",
):
    assert "HERMES_CREDENTIAL_MASTER_KEY" not in (ROOT / "charts/hermes-control-plane/templates" / pod_template).read_text(), pod_template
for template in (ROOT / "charts/hermes-control-plane/templates").glob("*.yaml"):
    text = template.read_text()
    assert "<<<<<<<" not in text and ">>>>>>>" not in text and "=======" not in text

for workflow_path in (".github/workflows/validate.yml", ".github/workflows/publish-images.yml"):
    load_yaml(workflow_path)

publish = (ROOT / ".github/workflows/publish-images.yml").read_text()
contexts = re.findall(r"context:\s+\./([A-Za-z0-9_-]+)", publish)
assert set(contexts) == {
    "control-plane", "credential-service", "router-gateway", "smart-router",
    "execution-broker", "kubernetes-broker", "node-agent",
}
for context in contexts:
    assert (ROOT / context / "Dockerfile").is_file(), f"missing Dockerfile for {context}"
assert "secrets.DOCKERHUB_USERNAME" in publish
assert "secrets.DOCKERHUB_TOKEN" in publish
assert "ghcr.io" not in publish.lower()
assert "linux/amd64,linux/arm64" in publish
assert "push: ${{ github.event_name != 'pull_request' }}" in publish
validate_workflow = (ROOT / ".github/workflows/validate.yml").read_text()
assert "docker compose --env-file .env config" in validate_workflow
assert "helm lint charts/hermes-control-plane" in validate_workflow

for script in ("apply.sh", "validate.sh", "push.sh"):
    text = (ROOT / script).read_text()
    assert "<<<<<<<" not in text and ">>>>>>>" not in text

push = (ROOT / "push.sh").read_text().lower()
for forbidden in ("docker push", "docker buildx", "build-push-action", "ghcr.io"):
    assert forbidden not in push, forbidden

print("0.5.11-dev.2-config-static: PASS")
