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
assert chart["version"] == "0.5.11-dev.4"
assert str(chart["appVersion"]) == "0.5.11-dev.4"
assert str(values["imageTag"]) == "0.5.11-dev.4"
assert "VERSION=0.5.11-dev.4" in (ROOT / ".env.example").read_text()

compose = load_yaml("docker-compose.yml")
assert isinstance(compose, dict) and isinstance(compose.get("services"), dict)
services = compose["services"]
for required in ("control-plane", "credential-service", "router-gateway", "smart-router", "kubernetes-broker", "hermes", "node-agent"):
    assert required in services, required
assert (compose.get("networks") or {}).get("credential-net", {}).get("internal") is True
for llm_service in ("smart-router", "hermes", "router-gateway"):
    assert "HERMES_CREDENTIAL_MASTER_KEY" not in yaml.safe_dump(services[llm_service])

# Dev.4 is integrated into the existing Control Plane image; no untracked deployable service was introduced.
publish = (ROOT / ".github/workflows/publish-images.yml").read_text()
contexts = re.findall(r"context:\s+\./([A-Za-z0-9_-]+)", publish)
assert set(contexts) == {"control-plane", "credential-service", "router-gateway", "smart-router", "execution-broker", "kubernetes-broker", "node-agent"}
for context in contexts:
    assert (ROOT / context / "Dockerfile").is_file(), context

# Dev.3 data remains plus dev.4 fleet/provider/job/artifact/verification persistence.
db = (ROOT / "control-plane/src/hermes_control_plane/db.py").read_text()
for table in (
    "cluster_blueprints", "cluster_profiles", "clusters", "node_roles", "provisioning_runs",
    "addon_plans", "upgrade_plans", "backup_plans", "kubernetes_intelligence_snapshots",
    "infrastructure_providers", "fleet_target_snapshots", "operation_plans", "operation_jobs",
    "artifact_mirror_items", "verification_results",
):
    assert f"CREATE TABLE IF NOT EXISTS {table}" in db, table
assert "PRAGMA user_version = 8" in db

main = (ROOT / "control-plane/src/hermes_control_plane/main.py").read_text()
assert 'VERSION = "0.5.11-dev.4"' in main
assert 'BOT_SOURCE_CHANNELS = {"ui", "telegram", "hermes-bot", "api"}' in main
assert '"fleet_cloud_baremetal_network_artifact"' in main

ui = (ROOT / "control-plane/src/hermes_control_plane/static/index.html").read_text()
assert "0.5.11-dev.4" in ui
assert "Full Operations Center" in ui
assert "refreshOperationsCenter" in ui
assert "/v1/operations-center/overview" in ui

for workflow_path in (".github/workflows/validate.yml", ".github/workflows/publish-images.yml"):
    load_yaml(workflow_path)
validate_workflow = (ROOT / ".github/workflows/validate.yml").read_text()
assert "0.5.11-dev.4)" in validate_workflow
assert "scripts/acceptance/dev4-source-security-gate.py" in validate_workflow
assert "scripts/acceptance/dev4-config-static-gate.py" in validate_workflow

for script in ("apply.sh", "validate.sh", "push.sh"):
    raw = (ROOT / script).read_text()
    assert "<<<<<<<" not in raw and ">>>>>>>" not in raw
    assert "0.5.11-dev.4" in raw
assert "8547c44de4f6e8116d70f2690b50a50c895eba34" in (ROOT / "apply.sh").read_text()


# The packaged source manifest is a complete checksum inventory of every source file except itself.
manifest_path = ROOT / "MANIFEST.sha256"
manifest_entries: dict[str, str] = {}
for line in manifest_path.read_text().splitlines():
    digest, rel = line.split("  ", 1)
    assert re.fullmatch(r"[0-9a-f]{64}", digest), rel
    assert rel not in manifest_entries, rel
    manifest_entries[rel] = digest

# Compare the package manifest only against managed repository/release files.
# A real developer checkout legitimately contains Git metadata, virtualenvs,
# local secrets, backups, caches, and generated runtime data. Those must not
# become part of the release manifest or make the static gate fail.
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
    # Runtime state is intentionally outside the source manifest. Keep only
    # the repository placeholders that are part of the packaged source tree.
    if parts[0] == "data" and path.name != ".gitkeep":
        return False
    # Local validation runs may write logs here; checked-in evidence files
    # remain managed and therefore continue to be inventory/hash checked.
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

print("0.5.11-dev.4-config-static: PASS")
