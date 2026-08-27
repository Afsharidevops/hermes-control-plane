from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from fastapi import HTTPException

CREDENTIAL_ROOT = Path(os.getenv("HERMES_INFRASTRUCTURE_CREDENTIAL_ROOT", "/credentials/infrastructure"))
RUNTIME_ENABLED = os.getenv("HERMES_PROXMOX_VM_RUNTIME_ENABLED", "false").lower() == "true"
REQUEST_TIMEOUT = float(os.getenv("HERMES_PROXMOX_VM_REQUEST_TIMEOUT_SECONDS", "20"))
MAX_RESPONSE_BYTES = int(os.getenv("HERMES_PROXMOX_VM_MAX_RESPONSE_BYTES", "1048576"))
MAX_REQUEST_BODY_BYTES = int(os.getenv("HERMES_PROXMOX_VM_MAX_REQUEST_BODY_BYTES", "8192"))
MAX_REQUESTS = int(os.getenv("HERMES_PROXMOX_VM_MAX_REQUESTS_PER_EXECUTION", "32"))
TASK_POLL_ATTEMPTS = int(os.getenv("HERMES_PROXMOX_VM_TASK_POLL_ATTEMPTS", "30"))
TASK_POLL_DELAY_SECONDS = float(os.getenv("HERMES_PROXMOX_VM_TASK_POLL_DELAY_SECONDS", "2"))
VERIFY_ATTEMPTS = int(os.getenv("HERMES_PROXMOX_VM_VERIFY_ATTEMPTS", "5"))
VERIFY_DELAY_SECONDS = float(os.getenv("HERMES_PROXMOX_VM_VERIFY_DELAY_SECONDS", "1"))
MAX_SECRET_BYTES = 16_384
CRED_RE = re.compile(r"^cred_[A-Za-z0-9][A-Za-z0-9._-]{2,118}$")
SAFE_FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
SNAPSHOT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
NIC_SLOT_RE = re.compile(r"^net[0-7]$")
UPID_RE = re.compile(r"^UPID:[A-Za-z0-9._-]{1,64}:[A-Fa-f0-9]{8,16}:[A-Fa-f0-9]{1,16}:[A-Fa-f0-9]{8,16}:[^:]{1,64}:[^:]{0,128}:?$")
API_VERSION = "pve-8.2"
IMPLEMENTATION_VERSION = "pve-vm-runtime-v1"
OPERATIONS = {"vm.create", "vm.clone", "vm.update", "vm.delete", "vm.power", "network.attach", "snapshot.create", "snapshot.restore"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def _failure(status: int, code: str) -> HTTPException:
    return HTTPException(status, f"proxmox VM runtime failed: {code}")


def _safe_child(directory: Path, name: str) -> Path:
    if not SAFE_FILE_RE.fullmatch(name):
        raise _failure(503, "POLICY_DENIED")
    candidate = directory / name
    if candidate.is_symlink():
        raise _failure(503, "POLICY_DENIED")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise _failure(503, "AUTH_FAILED") from exc
    if resolved.parent != directory or not resolved.is_file():
        raise _failure(503, "POLICY_DENIED")
    return resolved


def _profile_directory(credential_ref: str) -> tuple[Path, dict[str, Any]]:
    if not CRED_RE.fullmatch(credential_ref):
        raise _failure(422, "POLICY_DENIED")
    try:
        root = CREDENTIAL_ROOT.resolve(strict=True)
        directory = (root / credential_ref).resolve(strict=True)
    except FileNotFoundError as exc:
        raise _failure(503, "AUTH_FAILED") from exc
    if directory.parent != root or not directory.is_dir():
        raise _failure(503, "POLICY_DENIED")
    try:
        raw = _safe_child(directory, "profile.json").read_bytes()
        profile = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise _failure(503, "AUTH_FAILED") from exc
    if len(raw) > MAX_SECRET_BYTES or not isinstance(profile, dict):
        raise _failure(503, "POLICY_DENIED")
    return directory, profile


def _secret(directory: Path, profile: dict[str, Any], field: str) -> str:
    name = profile.get(field)
    if not isinstance(name, str):
        raise _failure(503, "AUTH_FAILED")
    try:
        raw = _safe_child(directory, name).read_bytes()
        value = raw.decode("utf-8").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise _failure(503, "AUTH_FAILED") from exc
    if not value or len(raw) > MAX_SECRET_BYTES or any(ch in "\r\n" for ch in value):
        raise _failure(503, "AUTH_FAILED")
    return value


def _endpoint(value: Any) -> str:
    raw = str(value or "").rstrip("/")
    try:
        parsed = urllib.parse.urlparse(raw)
        port = parsed.port
    except ValueError as exc:
        raise _failure(422, "POLICY_DENIED") from exc
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or port != 8006 or parsed.path != "/api2/json"):
        raise _failure(422, "POLICY_DENIED")
    return raw


def _credential(provider: dict[str, Any]) -> dict[str, Any]:
    directory, profile = _profile_directory(str(provider.get("credential_ref") or ""))
    if set(profile) - {"version", "type", "token_id_file", "token_secret_file", "ca_file"} or profile.get("version") != 1 or profile.get("type") != "proxmox-api-token":
        raise _failure(503, "POLICY_DENIED")
    token_id = _secret(directory, profile, "token_id_file")
    token_secret = _secret(directory, profile, "token_secret_file")
    if len(token_id) > 160:
        raise _failure(503, "AUTH_FAILED")
    ca_file = None
    if profile.get("ca_file") is not None:
        if not isinstance(profile["ca_file"], str):
            raise _failure(503, "POLICY_DENIED")
        ca_file = _safe_child(directory, profile["ca_file"])
    return {"authorization": f"PVEAPIToken={token_id}={token_secret}", "ca_file": ca_file}


def _request(base: str, method: str, path: str, credential: dict[str, Any], requests: list[int], body: dict[str, Any] | None = None, *, allow_not_found: bool = False) -> dict[str, Any] | None:
    if requests[0] >= MAX_REQUESTS or method not in {"GET", "POST", "PUT", "DELETE"} or not path.startswith("/") or "?" in path or "#" in path:
        raise _failure(422, "POLICY_DENIED")
    requests[0] += 1
    payload = None
    headers = {"Accept": "application/json", "Authorization": credential["authorization"]}
    if body is not None:
        payload = urllib.parse.urlencode(body).encode()
        if len(payload) > MAX_REQUEST_BODY_BYTES:
            raise _failure(422, "POLICY_DENIED")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = urllib.request.Request(base + path, data=payload, headers=headers, method=method)
    try:
        context = ssl.create_default_context(cafile=str(credential["ca_file"]) if credential.get("ca_file") else None)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(), urllib.request.HTTPSHandler(context=context))
        with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
            content_type = str(response.headers.get("Content-Type") or "").lower()
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if allow_not_found and exc.code == 404:
            return None
        if 300 <= exc.code < 400:
            raise _failure(502, "UPSTREAM_UNAVAILABLE") from exc
        if exc.code in {401, 403}:
            raise _failure(502, "AUTH_FAILED") from exc
        raise _failure(502, "UPSTREAM_UNAVAILABLE") from exc
    except (OSError, TimeoutError, urllib.error.URLError, ssl.SSLError) as exc:
        raise _failure(502, "UPSTREAM_UNAVAILABLE") from exc
    if len(raw) > MAX_RESPONSE_BYTES or "json" not in content_type:
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID") from exc
    if not isinstance(result, dict) or "data" not in result:
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    return result


def _int(value: Any, *, low: int, high: int, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise _failure(422, f"INVALID_{field.upper()}")
    return value


def validate_desired(operation: str, desired: dict[str, Any]) -> dict[str, Any]:
    if operation not in OPERATIONS or not isinstance(desired, dict):
        raise _failure(422, "POLICY_DENIED")
    def identifier(name: str) -> str:
        value = str(desired.get(name) or "")
        if not ID_RE.fullmatch(value):
            raise _failure(422, f"INVALID_{name.upper()}")
        return value
    if operation == "vm.create":
        required = {"vm_id", "node", "name", "cpu_cores", "memory_mib", "storage", "disk_gib"}
        if not required <= set(desired) or set(desired) - (required | {"bridge"}):
            raise _failure(422, "POLICY_DENIED")
        result = {"vm_id": _int(desired.get("vm_id"), low=100, high=2_147_483_647, field="vm_id"), "node": identifier("node"), "name": identifier("name"), "cpu_cores": _int(desired.get("cpu_cores"), low=1, high=128, field="cpu_cores"), "memory_mib": _int(desired.get("memory_mib"), low=512, high=1_048_576, field="memory_mib"), "storage": identifier("storage"), "disk_gib": _int(desired.get("disk_gib"), low=8, high=65_536, field="disk_gib")}
        if "bridge" in desired:
            result["bridge"] = identifier("bridge")
        return result
    if operation == "vm.clone":
        if set(desired) != {"source_vm_id", "source_node", "target_vm_id", "target_node", "storage", "name"}:
            raise _failure(422, "POLICY_DENIED")
        return {"source_vm_id": _int(desired.get("source_vm_id"), low=100, high=2_147_483_647, field="source_vm_id"), "source_node": identifier("source_node"), "target_vm_id": _int(desired.get("target_vm_id"), low=100, high=2_147_483_647, field="target_vm_id"), "target_node": identifier("target_node"), "storage": identifier("storage"), "name": identifier("name")}
    if operation == "vm.update":
        if not {"vm_id", "node"} <= set(desired) or set(desired) - {"vm_id", "node", "cpu_cores", "memory_mib", "onboot"} or len(desired) == 2:
            raise _failure(422, "POLICY_DENIED")
        result = {"vm_id": _int(desired.get("vm_id"), low=100, high=2_147_483_647, field="vm_id"), "node": identifier("node")}
        if "cpu_cores" in desired:
            result["cpu_cores"] = _int(desired["cpu_cores"], low=1, high=128, field="cpu_cores")
        if "memory_mib" in desired:
            result["memory_mib"] = _int(desired["memory_mib"], low=512, high=1_048_576, field="memory_mib")
        if "onboot" in desired:
            if not isinstance(desired["onboot"], bool):
                raise _failure(422, "INVALID_ONBOOT")
            result["onboot"] = desired["onboot"]
        return result
    if operation in {"vm.delete", "vm.power"}:
        expected = {"vm_id", "node", "confirm_vm_id"} if operation == "vm.delete" else {"vm_id", "node", "target_state"}
        if set(desired) != expected:
            raise _failure(422, "POLICY_DENIED")
        vm_id = _int(desired.get("vm_id"), low=100, high=2_147_483_647, field="vm_id")
        result = {"vm_id": vm_id, "node": identifier("node")}
        if operation == "vm.delete":
            if desired.get("confirm_vm_id") != vm_id:
                raise _failure(422, "CONFIRMATION_REQUIRED")
        else:
            state = str(desired.get("target_state") or "").lower()
            if state not in {"running", "stopped"}:
                raise _failure(422, "INVALID_TARGET_STATE")
            result["target_state"] = state
        return result
    if operation == "network.attach":
        if set(desired) != {"vm_id", "node", "slot", "bridge"}:
            raise _failure(422, "POLICY_DENIED")
        slot = str(desired.get("slot") or "")
        if not NIC_SLOT_RE.fullmatch(slot):
            raise _failure(422, "INVALID_SLOT")
        return {"vm_id": _int(desired.get("vm_id"), low=100, high=2_147_483_647, field="vm_id"), "node": identifier("node"), "slot": slot, "bridge": identifier("bridge")}
    if operation == "snapshot.create":
        expected = {"vm_id", "node", "snapshot"}
    else:
        expected = {"vm_id", "node", "snapshot", "confirm_vm_id", "confirm_snapshot"}
    if set(desired) != expected:
        raise _failure(422, "POLICY_DENIED")
    vm_id = _int(desired.get("vm_id"), low=100, high=2_147_483_647, field="vm_id")
    snapshot = str(desired.get("snapshot") or "")
    if not SNAPSHOT_RE.fullmatch(snapshot):
        raise _failure(422, "INVALID_SNAPSHOT")
    if operation == "snapshot.restore" and (desired.get("confirm_vm_id") != vm_id or desired.get("confirm_snapshot") != snapshot):
        raise _failure(422, "CONFIRMATION_REQUIRED")
    return {"vm_id": vm_id, "node": identifier("node"), "snapshot": snapshot}


def _policy(provider: dict[str, Any], desired: dict[str, Any], operation: str) -> dict[str, Any]:
    if str(provider.get("api_version") or "") != API_VERSION or str(provider.get("implementation_version") or "") != IMPLEMENTATION_VERSION:
        raise _failure(422, "POLICY_DENIED")
    caps = provider.get("capabilities") if isinstance(provider.get("capabilities"), dict) else {}
    allowed = {"profile", "node_allowlist", "storage_allowlist", "bridge_allowlist", "template_allowlist", "vm_id_min", "vm_id_max", "max_cpu_cores", "max_memory_mib", "max_disk_gib", "max_nics", "max_snapshots", "action_allowlist", "allow_vm_delete", "allow_snapshot_restore"}
    if set(caps) - allowed or caps.get("profile") != IMPLEMENTATION_VERSION:
        raise _failure(422, "POLICY_DENIED")
    def list_of_ids(field: str, *, minimum: int = 0) -> set[str]:
        values = caps.get(field)
        if not isinstance(values, list) or not minimum <= len(values) <= 128 or any(not isinstance(item, str) or not ID_RE.fullmatch(item) for item in values) or len(set(values)) != len(values):
            raise _failure(422, "POLICY_DENIED")
        return set(values)
    nodes, storage, bridges = list_of_ids("node_allowlist", minimum=1), list_of_ids("storage_allowlist", minimum=1), list_of_ids("bridge_allowlist")
    actions = caps.get("action_allowlist")
    if not isinstance(actions, list) or not actions or set(actions) - OPERATIONS or len(set(actions)) != len(actions) or operation not in set(actions):
        raise _failure(422, "POLICY_DENIED")
    low = _int(caps.get("vm_id_min"), low=100, high=2_147_483_647, field="vm_id_min")
    high = _int(caps.get("vm_id_max"), low=low, high=2_147_483_647, field="vm_id_max")
    for field in ("max_cpu_cores", "max_memory_mib", "max_disk_gib"):
        _int(caps.get(field), low=1, high=1_048_576, field=field)
    _int(caps.get("max_nics"), low=1, high=8, field="max_nics")
    _int(caps.get("max_snapshots"), low=1, high=128, field="max_snapshots")
    templates = caps.get("template_allowlist")
    if not isinstance(templates, list) or len(templates) > 128:
        raise _failure(422, "POLICY_DENIED")
    template_set: set[tuple[str, int]] = set()
    for item in templates:
        if not isinstance(item, dict) or set(item) != {"node", "vm_id"} or not ID_RE.fullmatch(str(item.get("node") or "")):
            raise _failure(422, "POLICY_DENIED")
        template_set.add((item["node"], _int(item.get("vm_id"), low=100, high=2_147_483_647, field="template_vm_id")))
    if len(template_set) != len(templates):
        raise _failure(422, "POLICY_DENIED")
    if not isinstance(caps.get("allow_vm_delete"), bool) or not isinstance(caps.get("allow_snapshot_restore"), bool):
        raise _failure(422, "POLICY_DENIED")
    check_ids = [desired[key] for key in ("vm_id", "target_vm_id") if key in desired]
    if any(not low <= item <= high for item in check_ids):
        raise _failure(422, "POLICY_DENIED")
    for field in ("node", "source_node", "target_node"):
        if field in desired and desired[field] not in nodes:
            raise _failure(422, "POLICY_DENIED")
    if "storage" in desired and desired["storage"] not in storage:
        raise _failure(422, "POLICY_DENIED")
    if "bridge" in desired and desired["bridge"] not in bridges:
        raise _failure(422, "POLICY_DENIED")
    if operation == "vm.clone" and (desired["source_node"], desired["source_vm_id"]) not in template_set:
        raise _failure(422, "POLICY_DENIED")
    if operation == "vm.delete" and caps["allow_vm_delete"] is not True:
        raise _failure(422, "POLICY_DENIED")
    if operation == "snapshot.restore" and caps["allow_snapshot_restore"] is not True:
        raise _failure(422, "POLICY_DENIED")
    for field, limit in (("cpu_cores", "max_cpu_cores"), ("memory_mib", "max_memory_mib"), ("disk_gib", "max_disk_gib")):
        if field in desired and desired[field] > caps[limit]:
            raise _failure(422, "POLICY_DENIED")
    return {"nodes": nodes, "storage": storage, "bridges": bridges, "max_nics": caps["max_nics"], "max_snapshots": caps["max_snapshots"]}


def validate_provider(provider: dict[str, Any], desired: dict[str, Any], operation: str) -> dict[str, Any]:
    if not RUNTIME_ENABLED:
        raise _failure(503, "POLICY_DENIED")
    if str(provider.get("kind") or "") != "proxmox" or str(provider.get("status") or "") != "configured":
        raise _failure(422, "POLICY_DENIED")
    _endpoint(provider.get("endpoint"))
    return _policy(provider, desired, operation)


def _data(result: dict[str, Any] | None) -> Any:
    if not isinstance(result, dict):
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    return result.get("data")


def _parse_disk(value: Any) -> dict[str, Any]:
    raw = str(value or "")
    storage, separator, remainder = raw.partition(":")
    size_match = re.search(r"(?:^|,)size=(\d+)G(?:,|$)", remainder)
    return {"storage": storage if ID_RE.fullmatch(storage) else "", "size_gib": int(size_match.group(1)) if size_match else 0}


def _parse_bridge(value: Any) -> str:
    match = re.search(r"(?:^|,)bridge=([A-Za-z0-9_.:-]+)(?:,|$)", str(value or ""))
    return match.group(1) if match and ID_RE.fullmatch(match.group(1)) else ""


def current(provider: dict[str, Any], desired: dict[str, Any], operation: str, credential: dict[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    _policy(provider, desired, operation)
    credential = credential or _credential(provider)
    base = _endpoint(provider.get("endpoint"))
    node = desired.get("node") or desired.get("target_node")
    vm_id = desired.get("vm_id") or desired.get("target_vm_id")
    requests = [0]
    config = _request(base, "GET", f"/nodes/{node}/qemu/{vm_id}/config", credential, requests, allow_not_found=True)
    if config is None:
        return {"present": False, "node": node, "vm_id": vm_id, "qemu": True}, credential
    config_data = _data(config)
    if not isinstance(config_data, dict):
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    status_data = _data(_request(base, "GET", f"/nodes/{node}/qemu/{vm_id}/status/current", credential, requests))
    if not isinstance(status_data, dict):
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    snapshots_data = _data(_request(base, "GET", f"/nodes/{node}/qemu/{vm_id}/snapshot", credential, requests))
    if not isinstance(snapshots_data, list) or len(snapshots_data) > 128:
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    snapshots = sorted(item.get("name") for item in snapshots_data if isinstance(item, dict) and isinstance(item.get("name"), str) and SNAPSHOT_RE.fullmatch(item["name"]))
    disk = _parse_disk(config_data.get("scsi0"))
    networks = {slot: _parse_bridge(config_data.get(slot)) for slot in [f"net{number}" for number in range(8)] if config_data.get(slot) is not None}
    try:
        cpu_cores = int(config_data.get("cores") or 0)
        memory_mib = int(config_data.get("memory") or 0)
    except (TypeError, ValueError) as exc:
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID") from exc
    power_state = str(status_data.get("status") or "").lower()
    if power_state not in {"running", "stopped"}:
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    return {"present": True, "node": node, "vm_id": vm_id, "qemu": True, "power_state": power_state, "cpu_cores": cpu_cores, "memory_mib": memory_mib, "onboot": str(config_data.get("onboot") or "0").lower() in {"1", "true"}, "disk": disk, "networks": networks, "snapshots": snapshots}, credential


def diff(operation: str, current_state: dict[str, Any], desired: dict[str, Any]) -> list[dict[str, Any]]:
    present = current_state.get("present") is True
    if operation in {"vm.create", "vm.clone"}:
        if not present:
            return [{"field": "vm.presence", "from": "absent", "to": "present"}]
        if operation == "vm.create":
            mismatches = [
                {"field": field, "from": current_state.get(field), "to": desired[field]}
                for field in ("cpu_cores", "memory_mib") if current_state.get(field) != desired[field]
            ]
            if current_state.get("disk", {}).get("storage") != desired["storage"] or current_state.get("disk", {}).get("size_gib") != desired["disk_gib"]:
                mismatches.append({"field": "boot_disk", "from": current_state.get("disk"), "to": {"storage": desired["storage"], "size_gib": desired["disk_gib"]}})
            if desired.get("bridge") and current_state.get("networks", {}).get("net0") != desired["bridge"]:
                mismatches.append({"field": "net0", "from": current_state.get("networks", {}).get("net0"), "to": desired["bridge"]})
            return mismatches
        return []

    if operation == "vm.delete":
        return [] if not present else [{"field": "vm.presence", "from": "present", "to": "absent"}]
    if not present:
        return [{"field": "vm.presence", "from": "absent", "to": "required"}]
    if operation == "vm.power":
        return [] if current_state.get("power_state") == desired["target_state"] else [{"field": "power_state", "from": current_state.get("power_state"), "to": desired["target_state"]}]
    if operation == "vm.update":
        return [{"field": key, "from": current_state.get(key), "to": value} for key, value in desired.items() if key in {"cpu_cores", "memory_mib", "onboot"} and current_state.get(key) != value]
    if operation == "network.attach":
        return [] if current_state.get("networks", {}).get(desired["slot"]) == desired["bridge"] else [{"field": desired["slot"], "from": current_state.get("networks", {}).get(desired["slot"]), "to": desired["bridge"]}]
    if operation == "snapshot.create":
        return [] if desired["snapshot"] in current_state.get("snapshots", []) else [{"field": "snapshot", "from": "absent", "to": desired["snapshot"]}]
    return [] if desired["snapshot"] not in current_state.get("snapshots", []) else [{"field": "snapshot.restore", "from": "current", "to": desired["snapshot"]}]


def _task(base: str, node: str, result: dict[str, Any] | None, credential: dict[str, Any], requests: list[int]) -> None:
    upid = _data(result)
    if not isinstance(upid, str) or not UPID_RE.fullmatch(upid) or not upid.startswith(f"UPID:{node}:"):
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    encoded = urllib.parse.quote(upid, safe="")
    for attempt in range(max(1, TASK_POLL_ATTEMPTS)):
        task = _data(_request(base, "GET", f"/nodes/{node}/tasks/{encoded}/status", credential, requests))
        if not isinstance(task, dict):
            raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
        if int(task.get("status") or 0) == 1:
            if str(task.get("exitstatus") or "") != "OK":
                raise _failure(502, "UPSTREAM_UNAVAILABLE")
            return
        if attempt + 1 < max(1, TASK_POLL_ATTEMPTS):
            time.sleep(max(0.0, TASK_POLL_DELAY_SECONDS))
    raise _failure(502, "UPSTREAM_UNAVAILABLE")


def ensure_mutation_precondition(operation: str, current_state: dict[str, Any], desired: dict[str, Any], policy: dict[str, Any]) -> None:
    if operation in {"vm.delete", "snapshot.restore"} and current_state.get("present") is True and current_state.get("power_state") != "stopped":
        raise _failure(409, "VM_MUST_BE_STOPPED")
    if operation == "network.attach" and current_state.get("present") is True:
        if desired["slot"] not in current_state.get("networks", {}) and len(current_state.get("networks") or {}) >= policy["max_nics"]:
            raise _failure(409, "NIC_LIMIT_REACHED")
    if operation == "snapshot.create" and current_state.get("present") is True:
        if len(current_state.get("snapshots") or []) >= policy["max_snapshots"]:
            raise _failure(409, "SNAPSHOT_LIMIT_REACHED")


def enforce_current_policy(provider: dict[str, Any], current_state: dict[str, Any], desired: dict[str, Any], operation: str) -> None:
    ensure_mutation_precondition(operation, current_state, desired, _policy(provider, desired, operation))




def apply(provider: dict[str, Any], desired: dict[str, Any], operation: str, credential: dict[str, Any]) -> None:
    _policy(provider, desired, operation)
    base = _endpoint(provider.get("endpoint"))
    requests = [0]
    node = desired.get("node") or desired.get("target_node")
    vm_id = desired.get("vm_id") or desired.get("target_vm_id")
    if operation == "vm.create":
        body = {"vmid": str(desired["vm_id"]), "name": desired["name"], "cores": str(desired["cpu_cores"]), "memory": str(desired["memory_mib"]), "scsi0": f"{desired['storage']}:{desired['disk_gib']}", "ostype": "l26"}
        if desired.get("bridge"):
            body["net0"] = f"virtio,bridge={desired['bridge']}"
        result = _request(base, "POST", f"/nodes/{node}/qemu", credential, requests, body)
    elif operation == "vm.clone":
        result = _request(base, "POST", f"/nodes/{desired['source_node']}/qemu/{desired['source_vm_id']}/clone", credential, requests, {"newid": str(vm_id), "name": desired["name"], "target": node, "storage": desired["storage"], "full": "1"})
    elif operation == "vm.update":
        body = {key: ("1" if value else "0") if isinstance(value, bool) else str(value) for key, value in desired.items() if key in {"cpu_cores", "memory_mib", "onboot"}}
        mapping = {"cpu_cores": "cores", "memory_mib": "memory"}
        body = {mapping.get(key, key): value for key, value in body.items()}
        result = _request(base, "PUT", f"/nodes/{node}/qemu/{vm_id}/config", credential, requests, body)
    elif operation == "vm.delete":
        result = _request(base, "DELETE", f"/nodes/{node}/qemu/{vm_id}", credential, requests, {"purge": "0", "destroy-unreferenced-disks": "0"})
    elif operation == "vm.power":
        action = "start" if desired["target_state"] == "running" else "shutdown"
        result = _request(base, "POST", f"/nodes/{node}/qemu/{vm_id}/status/{action}", credential, requests)
    elif operation == "network.attach":
        result = _request(base, "PUT", f"/nodes/{node}/qemu/{vm_id}/config", credential, requests, {desired["slot"]: f"virtio,bridge={desired['bridge']}"})
    elif operation == "snapshot.create":
        result = _request(base, "POST", f"/nodes/{node}/qemu/{vm_id}/snapshot", credential, requests, {"snapname": desired["snapshot"]})
    else:
        result = _request(base, "POST", f"/nodes/{node}/qemu/{vm_id}/snapshot/{desired['snapshot']}/rollback", credential, requests)
    _task(base, node, result, credential, requests)


def verify(current_state: dict[str, Any], desired: dict[str, Any], operation: str) -> bool:
    if operation == "vm.create":
        return (
            current_state.get("present") is True
            and current_state.get("cpu_cores") == desired["cpu_cores"]
            and current_state.get("memory_mib") == desired["memory_mib"]
            and current_state.get("disk", {}).get("storage") == desired["storage"]
            and current_state.get("disk", {}).get("size_gib") == desired["disk_gib"]
            and (not desired.get("bridge") or current_state.get("networks", {}).get("net0") == desired["bridge"])
        )
    if operation == "vm.clone":
        return current_state.get("present") is True
    if operation == "vm.delete":
        return current_state.get("present") is False
    if current_state.get("present") is not True:
        return False
    if operation == "vm.power":
        return current_state.get("power_state") == desired["target_state"]
    if operation == "vm.update":
        return all(current_state.get(key) == value for key, value in desired.items() if key in {"cpu_cores", "memory_mib", "onboot"})
    if operation == "network.attach":
        return current_state.get("networks", {}).get(desired["slot"]) == desired["bridge"]
    if operation == "snapshot.create":
        return desired["snapshot"] in current_state.get("snapshots", [])
    return desired["snapshot"] in current_state.get("snapshots", [])
