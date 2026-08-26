from __future__ import annotations

import hashlib
import json
import math
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
COLLECTION_ENABLED = os.getenv("HERMES_CAPACITY_COLLECTION_ENABLED", "false").lower() == "true"
REQUEST_TIMEOUT = float(os.getenv("HERMES_CAPACITY_REQUEST_TIMEOUT_SECONDS", "20"))
MAX_RESPONSE_BYTES = int(os.getenv("HERMES_CAPACITY_MAX_RESPONSE_BYTES", "1048576"))
MAX_REQUESTS = int(os.getenv("HERMES_CAPACITY_MAX_REQUESTS", "8"))
MAX_RESOURCES = 64
MAX_SECRET_BYTES = 16_384
CRED_RE = re.compile(r"^cred_[A-Za-z0-9][A-Za-z0-9._-]{2,118}$")
SAFE_FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
PROVIDER_ID_RE = re.compile(r"^ipr_[A-Za-z0-9][A-Za-z0-9._-]{2,118}$")
SCOPE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")

# A collector is added only after its endpoint/profile contract is implemented and reviewed.
# VMware Workstation has no supported remote collector and remains contract-only.
PROVIDER_PINS = {"proxmox": ("pve-8.2", "pve-capacity-v1")}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _failure(status: int, code: str) -> HTTPException:
    return HTTPException(status, f"capacity refresh failed: {code}")


def _valid_configuration() -> bool:
    return 0 < REQUEST_TIMEOUT <= 60 and 4096 <= MAX_RESPONSE_BYTES <= 1_048_576 and 1 <= MAX_REQUESTS <= 8


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


def _url(base: str, path: str, query: dict[str, str]) -> str:
    if path != "/cluster/resources" or query != {"type": "node"}:
        raise _failure(422, "POLICY_DENIED")
    parsed = urllib.parse.urlparse(base)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path + path, "", urllib.parse.urlencode(query), ""))


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


def _number(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)) or float(value) < 0:
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    return float(value)


def _resource(scope_id: str, resource: str, unit: str, limit: Any, used: Any) -> dict[str, Any]:
    if not SCOPE_ID_RE.fullmatch(scope_id):
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    limit_value = _number(limit)
    used_value = _number(used)
    if used_value > limit_value:
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    return {
        "scope_id": scope_id,
        "resource": resource,
        "unit": unit,
        "limit": limit_value,
        "used": used_value,
        "reserved": None,
        "headroom": limit_value - used_value,
        "semantics": "host_utilization",
    }


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


def _proxmox(snapshot: dict[str, Any], caps: dict[str, Any], directory: Path, profile: dict[str, Any], requests: list[int]) -> list[dict[str, Any]]:
    if set(profile) - {"version", "type", "token_id_file", "token_secret_file", "ca_file"} or profile.get("type") != "proxmox-api-token":
        raise _failure(503, "POLICY_DENIED")
    token_id = _secret(directory, profile, "token_id_file")
    token_secret = _secret(directory, profile, "token_secret_file")
    if len(token_id) > 160 or len(token_secret) > MAX_SECRET_BYTES or any(ch in "\r\n" for ch in token_id + token_secret):
        raise _failure(503, "AUTH_FAILED")
    endpoint = _endpoint(snapshot["endpoint"])
    raw = _request(
        _url(endpoint, "/cluster/resources", {"type": "node"}),
        authorization=f"PVEAPIToken={token_id}={token_secret}",
        ca_file=_ca_file(directory, profile),
        requests=requests,
    )
    data = raw.get("data")
    if not isinstance(data, list) or len(data) > 128:
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    returned = {item.get("node"): item for item in data if isinstance(item, dict) and isinstance(item.get("node"), str)}
    nodes = caps["node_allowlist"]
    if set(nodes) - set(returned):
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    resources: list[dict[str, Any]] = []
    for node in sorted(nodes):
        item = returned[node]
        cpu_ratio = _number(item.get("cpu"))
        if cpu_ratio > 1:
            raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
        max_cpu = _number(item.get("maxcpu"))
        resources.extend((
            _resource(node, "cpu", "cores", max_cpu, max_cpu * cpu_ratio),
            _resource(node, "memory", "bytes", item.get("maxmem"), item.get("mem")),
        ))
    return resources


def collect(provider_snapshot: dict[str, Any]) -> dict[str, Any]:
    snapshot, caps, directory, profile = _provider(provider_snapshot)
    requests = [0]
    resources = _proxmox(snapshot, caps, directory, profile, requests)
    if len(resources) != len(caps["node_allowlist"]) * 2 or len(resources) > MAX_RESOURCES:
        raise _failure(502, "UPSTREAM_SCHEMA_INVALID")
    result = {
        "schema_version": 1,
        "operation": "capacity.refresh",
        "observation_state": "LIVE",
        "provider": {
            "id": snapshot["id"],
            "kind": "proxmox",
            "api_version": snapshot["api_version"],
            "implementation_version": snapshot["implementation_version"],
            "snapshot_hash": snapshot["snapshot_hash"],
        },
        "observed_at": int(time.time()),
        "capacity_kind": "host_utilization",
        "coverage": "allowlisted_nodes",
        "scope": {"node_count": len(caps["node_allowlist"])},
        "resources": resources,
        "source": {"adapter": "proxmox-api-token-v1", "endpoint_profile": "pve-8.2", "request_count": requests[0]},
        "credential_material_returned": False,
        "mutation_commands_executed": False,
        "arbitrary_cli": False,
        "arbitrary_shell": False,
    }
    return {**result, "observation_hash": sha256_hex(result)}
