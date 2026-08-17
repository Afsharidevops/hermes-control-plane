#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


version = (ROOT / "VERSION").read_text().strip()
require(version == "0.5.11-dev.1", f"VERSION must be 0.5.11-dev.1, got {version!r}")

compose_text = (ROOT / "docker-compose.yml").read_text()
compose = yaml.safe_load(compose_text)
services = compose.get("services", {})
for name, service in services.items():
    mounts = [str(v) for v in service.get("volumes", [])]
    if name in {"smart-router", "control-plane", "hermes", "router-gateway"}:
        require(not any("docker.sock" in mount for mount in mounts), f"forbidden Docker socket in LLM-facing service {name}")
    require(service.get("privileged") is not True, f"privileged container forbidden in stable compose: {name}")

require("HERMES_EXECUTION_ENABLED: ${HERMES_EXECUTION_ENABLED:-false}" in compose_text, "Control Plane execution must default off")
require("HERMES_KUBERNETES_EXECUTION_ENABLED: ${HERMES_KUBERNETES_EXECUTION_ENABLED:-false}" in compose_text, "Kubernetes execution must default off")
for marker in ["HERMES_BOT_SERVICE_TOKEN", "HERMES_APPROVAL_BOT_TOKEN", "HERMES_APPROVAL_HMAC_KEY", "HERMES_AGENT_TASK_HMAC_KEY"]:
    require(marker in compose_text, f"Compose missing {marker}")

models = (ROOT / "control-plane/src/hermes_control_plane/models.py").read_text()
change_model = models.split("class ChangeSetCreate", 1)[1].split("class PolicyGenerationBump", 1)[0]
require("policy_generation" not in change_model, "ChangeSetCreate must not accept caller-selected policy_generation")

main = (ROOT / "control-plane/src/hermes_control_plane/main.py").read_text()
for marker in [
    "_require_current_policy_generation",
    "_approval_hmac_key",
    "consumed_at",
    "agent nonce replay rejected",
    "/v1/agents/enrollment-tokens",
    "/v1/audit/export",
    "/v1/audit/retention",
    "/v1/applications",
    "/v1/capabilities",
    "/v1/agents/tasks/{task_id}/claim",
    "_agent_task_signature",
]:
    require(marker in main, f"stable security marker missing: {marker}")

chart = (ROOT / "charts/hermes-control-plane/templates/control-plane.yaml").read_text()
secret = (ROOT / "charts/hermes-control-plane/templates/secret.yaml").read_text()
values = (ROOT / "charts/hermes-control-plane/values.yaml").read_text()
for marker in ["HERMES_BOT_SERVICE_TOKEN", "HERMES_APPROVAL_BOT_TOKEN", "HERMES_APPROVAL_HMAC_KEY", "HERMES_AGENT_TASK_HMAC_KEY"]:
    require(marker in chart, f"Helm Control Plane missing {marker}")
for marker in ["bot-service-token", "approval-bot-token", "approval-hmac-key", "agent-task-hmac-key"]:
    require(marker in secret, f"Helm Secret missing {marker}")
require("executionEnabled: false" in values, "Helm Control Plane execution must default off")
require("executionEnabled: false" in values.split("kubernetesBroker:", 1)[1], "Helm Kubernetes Broker execution must default off")
require("activeProvider: nine-router" in values and "omniroute:" in values, "Helm must expose both router providers")
require("profiles: [\"nine-router\"]" in compose_text and "profiles: [\"omniroute\"]" in compose_text, "Compose must expose both router providers")

print("0.5.11-dev.1-source-security: PASS")
