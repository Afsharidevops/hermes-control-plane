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
COLLECTION_ENABLED = os.getenv("HERMES_VM_INVENTORY_COLLECTION_ENABLED", "false").lower() == "true"
REQUEST_TIMEOUT = float(os.getenv("HERMES_VM_INVENTORY_REQUEST_TIMEOUT_SECONDS", "20"))
MAX_RESPONSE_BYTES = int(os.getenv("HERMES_VM_INVENTORY_MAX_RESPONSE_BYTES", "1048576"))
MAX_REQUESTS = 2
MAX_VMS = 512
MAX_SECRET_BYTES = 16_384
CRED_RE = re.compile(r"^cred_[A-Za-z0-9][A-Za-z0-9._-]{2,118}$")
SAFE_FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
PROVIDER_ID_RE = re.compile(r"^ipr_[A-Za-z0-9][A-Za-z0-9._-]{2,118}$")
SCOPE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
PROVIDER_PINS = {"proxmox": ("pve-8.2", "pve-vm-inventory-v1")}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _failure(status: int, code: str) -> HTTPException:
    return HTTPException(status, f"vm inventory refresh failed: {code}")


def _valid_configuration() -> bool:
    return 0 < REQUEST_TIMEOUT <= 60 and 4096 <= MAX_RESPONSE_BYTES <= 1_048_576


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
    except FileNotFoundError as exc:
        raise _failure(503, "AUTH_FAILED") from exc
    candidate = root / credential_ref
    if candidate.is_symlink():
        raise _failure(503, "POLICY_DENIED")
    try:
        directory = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise _failure(503, "AUTH_FAILED") from exc
    if directory.parent != root or not directory.is_dir():
        raise _failure(503, "POLICY_DENIED")
    profile_path = _safe_child(directory, "profile.json")
    try:
        raw_profile = profile_path.read_bytes()
        if len(raw_profile) > MAX_SECRET_BYTES:
            raise _failure(503, "POLICY_DENIED")
        profile = json.loads(raw_profile.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise _failure(503, "AUTH_FAILED") from exc
    if not isinstance(profile, dict) or profile.get("version") != 1:
        raise _failure(503, "POLICY_DENIED")
    return directory, profile


def _secret(directory: Path, profile: dict[str, Any], field: str) -> str:
    name = profile.get(field)
    if not isinstance(name, str):
        raise _failure(503, "AUTH_FAILED")
    try:
        raw = _safe_child(directory, name).read_bytes()
    except OSError as exc:
        raise _failure(503, "AUTH_FAILED") from exc
    if len(raw) > MAX_SECRET_BYTES:
        raise _failure(503, "POLICY_DENIED")
    try:
        value = raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise _failure(503, "AUTH_FAILED") from exc
    if not value:
        raise _failure(503, "AUTH_FAILED")
    return value


def _ca_file(directory: Path, profile: dict[str, Any]) -> Path | None:
    name = profile.get("ca_file")
    if name is None:
        return None
    if not isinstance(name, str):
        raise _failure(503, "POLICY_DENIED")
    return _safe_child(directory, name)


def _endpoint(value: Any) -> str:
    raw = str(value or "").rstrip("/")
    try:
        parsed = urllib.parse.urlparse(raw)
        port = parsed.port
    except ValueError as exc:
        raise _failure(422, "POLICY_DENIED") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or port != 8006
        or parsed.path != "/api2/json"
    ):
        raise _failure(422, "POLICY_DENIED")
    return raw


def _url(base: str, resource_type: str) -> str:
    if resource_type not in {"node", "vm"}:
        raise _failure(422, "POLICY_DENIED")
    parsed = urllib.parse.urlparse(base)
    return urllib.parse.urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path + "/cluster/resources",
        "",
        urllib.parse.urlencode({"type": resource_type}),
        "",
    ))


def _request(url: str, *, authorization: str, ca_file: Path | None, requests: list[int]) -> dict[str, Any]:
    if requests[0] >= MAX_REQUESTS:
        raise _failure(502, "PAGINATION_LIMIT")
    requests[0] += 1
    request = urllib.request.Request(url, headers={"Accept": "application/json", "Authorization": authorization}, method="GET")
    try:
        context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
    except (OSError, ssl.SSLError) as exc:
        raise _failure(503, "POLICY_DENIED") from exc
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(), urllib.request.HTTPSHandler(context=context))
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
            content_type = str(response.headers.get("Content-Type") or "").lower()
            data = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise _failure(502, "UPSTREAM_UNAVAILABLE") from exc
        if exc.code in {401, 403}:
            raise _failure(502, "AUTH_FAILED") from exc
        raise _failure(502, "UPSTREAM_UNAVAILABLE") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise _failure(502, "UPSTREAM_UNAVAILABLE") from exc
    if len(data) > MAX_RESPONSE_BYTES:
        raise _failure(502, "RESPONSE_LIMIT")
    if "json" not in content_type:
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    try:
        result = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID") from exc
    if not isinstance(result, dict):
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    return result


def _provider(snapshot: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], Path, dict[str, Any]]:
    if not COLLECTION_ENABLED or not _valid_configuration() or not isinstance(snapshot, dict):
        raise _failure(503, "POLICY_DENIED")
    expected_hash = snapshot.get("snapshot_hash")
    unsigned = dict(snapshot)
    unsigned.pop("snapshot_hash", None)
    if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash) or sha256_hex(unsigned) != expected_hash:
        raise _failure(422, "POLICY_DENIED")
    provider_id = str(snapshot.get("id") or "")
    kind = str(snapshot.get("kind") or "")
    if not PROVIDER_ID_RE.fullmatch(provider_id) or kind not in PROVIDER_PINS or snapshot.get("status") != "configured":
        raise _failure(422, "POLICY_DENIED")
    if (snapshot.get("api_version"), snapshot.get("implementation_version")) != PROVIDER_PINS[kind]:
        raise _failure(422, "POLICY_DENIED")
    credential_snapshot = snapshot.get("credential_snapshot")
    credential_ref = snapshot.get("credential_ref")
    if not isinstance(credential_snapshot, dict) or credential_snapshot.get("status") != "configured" or credential_ref != credential_snapshot.get("id"):
        raise _failure(422, "POLICY_DENIED")
    caps = snapshot.get("capabilities")
    if not isinstance(caps, dict) or set(caps) != {"node_allowlist"}:
        raise _failure(422, "POLICY_DENIED")
    nodes = caps["node_allowlist"]
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= 32 or len(set(nodes)) != len(nodes) or any(not isinstance(node, str) or not SCOPE_ID_RE.fullmatch(node) for node in nodes):
        raise _failure(422, "POLICY_DENIED")
    _endpoint(snapshot.get("endpoint"))
    directory, profile = _profile_directory(str(credential_ref or ""))
    return snapshot, caps, directory, profile


def _data(raw: dict[str, Any]) -> list[dict[str, Any]]:
    data = raw.get("data")
    if not isinstance(data, list):
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    if any(not isinstance(item, dict) for item in data):
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    return data


def _vm_record(item: dict[str, Any], nodes: set[str]) -> dict[str, Any] | None:
    node = item.get("node")
    if not isinstance(node, str):
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    if node not in nodes:
        return None
    vm_id = item.get("vmid")
    vm_type = item.get("type")
    status = item.get("status")
    template = item.get("template", False)
    if (
        not isinstance(vm_id, int)
        or isinstance(vm_id, bool)
        or not 1 <= vm_id <= 2_147_483_647
        or vm_type not in {"qemu", "lxc"}
        or status not in {"running", "stopped"}
        or not isinstance(template, (bool, int))
        or isinstance(template, int) and template not in {0, 1}
    ):
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    return {"vm_id": vm_id, "node": node, "type": vm_type, "power_state": status, "template": bool(template)}


def _proxmox(snapshot: dict[str, Any], caps: dict[str, Any], directory: Path, profile: dict[str, Any], requests: list[int]) -> list[dict[str, Any]]:
    if set(profile) - {"version", "type", "token_id_file", "token_secret_file", "ca_file"} or profile.get("type") != "proxmox-api-token":
        raise _failure(503, "POLICY_DENIED")
    token_id = _secret(directory, profile, "token_id_file")
    token_secret = _secret(directory, profile, "token_secret_file")
    if len(token_id) > 160 or len(token_secret) > MAX_SECRET_BYTES or any(ch in "\r\n" for ch in token_id + token_secret):
        raise _failure(503, "AUTH_FAILED")
    endpoint = _endpoint(snapshot["endpoint"])
    authorization = f"PVEAPIToken={token_id}={token_secret}"
    nodes = set(caps["node_allowlist"])
    node_data = _data(_request(_url(endpoint, "node"), authorization=authorization, ca_file=_ca_file(directory, profile), requests=requests))
    returned_nodes = {item.get("node") for item in node_data if isinstance(item.get("node"), str)}
    if nodes - returned_nodes:
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    vm_data = _data(_request(_url(endpoint, "vm"), authorization=authorization, ca_file=_ca_file(directory, profile), requests=requests))
    if len(vm_data) > MAX_VMS:
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    records = [record for item in vm_data if (record := _vm_record(item, nodes)) is not None]
    if len(records) > MAX_VMS or len({record["vm_id"] for record in records}) != len(records):
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    return sorted(records, key=lambda record: (record["node"], record["vm_id"]))


def collect(provider_snapshot: dict[str, Any]) -> dict[str, Any]:
    snapshot, caps, directory, profile = _provider(provider_snapshot)
    requests = [0]
    records = _proxmox(snapshot, caps, directory, profile, requests)
    if requests[0] != MAX_REQUESTS:
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    result = {
        "schema_version": 1,
        "operation": "vm.inventory.refresh",
        "observation_state": "LIVE",
        "provider": {
            "id": snapshot["id"],
            "kind": "proxmox",
            "api_version": snapshot["api_version"],
            "implementation_version": snapshot["implementation_version"],
            "snapshot_hash": snapshot["snapshot_hash"],
        },
        "observed_at": int(time.time()),
        "inventory_kind": "virtual_machine_identity_state",
        "coverage": "allowlisted_nodes",
        "scope": {"node_count": len(caps["node_allowlist"]), "vm_count": len(records)},
        "records": records,
        "source": {"adapter": "proxmox-api-token-v1", "endpoint_profile": "pve-8.2", "request_count": requests[0]},
        "credential_material_returned": False,
        "mutation_commands_executed": False,
        "arbitrary_cli": False,
        "arbitrary_shell": False,
    }
    return {**result, "observation_hash": sha256_hex(result)}
