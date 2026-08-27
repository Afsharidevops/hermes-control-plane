from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

import httpx


MCP_PROTOCOL_VERSION = "2025-03-26"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
READ_TOOLS = {
    "get_dashboard",
    "get_neighborhood",
    "get_resource",
    "get_topology",
    "issues",
    "list_resources",
    "search",
}
_TOOL_ARGUMENTS: dict[str, set[str]] = {
    "get_dashboard": {"namespace"},
    "list_resources": {"kind", "group", "namespace", "context"},
    "search": {"query", "filter", "limit"},
    "issues": {"namespace", "severity", "kind", "filter", "limit"},
    "get_resource": {"kind", "namespace", "name", "group", "include", "context"},
    "get_topology": {"namespace", "view", "format"},
    "get_neighborhood": {"kind", "namespace", "name", "profile", "hops"},
}
_SECRET_KEYS = {
    "authorization",
    "access_token",
    "api_key",
    "apikey",
    "client_secret",
    "credential",
    "credentials",
    "kubeconfig",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "secret_key",
    "token",
}
_SECRET_TEXT_PATTERNS = (
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+\-/]+=*"),
    re.compile(r"(?i)((?:api[_-]?key|access[_-]?token|client[_-]?secret|password|token)\s*[:=]\s*)[^\s,;]+"),
)


class RadarError(RuntimeError):
    pass


class RadarUnavailable(RadarError):
    pass


class RadarProtocolError(RadarError):
    pass


def _endpoint(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RadarProtocolError("Radar endpoint must be an http/https URL")
    if parsed.username is not None or parsed.password is not None:
        raise RadarProtocolError("Radar endpoint must not contain embedded credentials")
    return value.rstrip("/")


def validate_read_tool(tool: str, arguments: dict[str, Any]) -> None:
    if tool not in READ_TOOLS:
        raise RadarProtocolError(f"Radar tool is not allowlisted for read-only Hermes use: {tool}")
    allowed = _TOOL_ARGUMENTS[tool]
    unexpected = sorted(set(arguments) - allowed)
    if unexpected:
        raise RadarProtocolError(f"unsupported Radar arguments for {tool}: {', '.join(unexpected)}")

    for key, value in arguments.items():
        if isinstance(value, str) and len(value) > 1000:
            raise RadarProtocolError(f"Radar argument {key} is too long")
    if "limit" in arguments:
        limit = arguments["limit"]
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 200:
            raise RadarProtocolError("Radar limit must be an integer from 1 to 200")
    if tool == "search" and not str(arguments.get("query", "")).strip():
        raise RadarProtocolError("Radar search requires a non-empty query")
    if tool in {"list_resources", "get_resource", "get_neighborhood"} and not str(arguments.get("kind", "")).strip():
        raise RadarProtocolError(f"Radar {tool} requires kind")
    if tool in {"get_resource", "get_neighborhood"} and not str(arguments.get("name", "")).strip():
        raise RadarProtocolError(f"Radar {tool} requires name")
    if "hops" in arguments:
        hops = arguments["hops"]
        if not isinstance(hops, int) or isinstance(hops, bool) or not 1 <= hops <= 2:
            raise RadarProtocolError("Radar neighborhood hops must be 1 or 2")


def _scrub_text(value: str) -> str:
    result = value
    for pattern in _SECRET_TEXT_PATTERNS:
        result = pattern.sub(lambda match: f"{match.group(1)}[REDACTED]", result)
    if len(result) > 1_000_000:
        result = result[:1_000_000] + "\n[TRUNCATED BY HERMES]"
    return result


def redact(value: Any) -> Any:
    """Defense-in-depth redaction for all Radar/native intelligence before UI/AI use."""
    if isinstance(value, dict):
        kind = str(value.get("kind", "")).lower()
        result: dict[str, Any] = {}
        for key, child in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if kind == "secret" and normalized in {"data", "stringdata", "string_data"}:
                result[key] = "[REDACTED]"
                continue
            if normalized in _SECRET_KEYS or normalized.endswith("_password") or normalized.endswith("_token") or normalized.endswith("_secret") or normalized.endswith("_private_key"):
                result[key] = "[REDACTED]"
                continue
            if normalized == "env" and isinstance(child, list):
                redacted_env: list[Any] = []
                for item in child:
                    if isinstance(item, dict):
                        entry = {k: redact(v) for k, v in item.items() if str(k).lower() != "value"}
                        if "value" in item:
                            entry["value"] = "[REDACTED]"
                        redacted_env.append(entry)
                    else:
                        redacted_env.append(redact(item))
                result[key] = redacted_env
                continue
            result[key] = redact(child)
        return result
    if isinstance(value, list):
        return [redact(item) for item in value[:1000]]
    if isinstance(value, str):
        stripped = value.strip()
        if stripped and stripped[0] in "[{" and len(stripped) <= 1_000_000:
            try:
                parsed = json.loads(stripped)
            except ValueError:
                pass
            else:
                return json.dumps(redact(parsed), sort_keys=True, separators=(",", ":"))
        return _scrub_text(value)
    return value


def _response_json(response: httpx.Response) -> dict[str, Any]:
    if len(response.content) > MAX_RESPONSE_BYTES:
        raise RadarProtocolError("Radar response exceeded the Hermes intelligence size limit")
    if response.status_code >= 500:
        raise RadarUnavailable(f"Radar returned HTTP {response.status_code}")
    if response.status_code >= 400:
        raise RadarProtocolError(f"Radar returned HTTP {response.status_code}")
    if not response.content:
        return {}

    content_type = response.headers.get("content-type", "").lower()
    if "text/event-stream" in content_type:
        candidates: list[dict[str, Any]] = []
        for line in response.text.splitlines():
            if not line.startswith("data:"):
                continue
            raw = line[5:].strip()
            if not raw:
                continue
            try:
                item = json.loads(raw)
            except ValueError:
                continue
            if isinstance(item, dict):
                candidates.append(item)
        if not candidates:
            raise RadarProtocolError("Radar MCP response did not contain a JSON-RPC event")
        return candidates[-1]

    try:
        payload = response.json()
    except ValueError as exc:
        raise RadarProtocolError("Radar MCP response was not valid JSON") from exc
    if not isinstance(payload, dict):
        raise RadarProtocolError("Radar MCP response must be a JSON object")
    return payload


def _unwrap(payload: dict[str, Any], request_id: int) -> dict[str, Any]:
    if payload.get("id") not in {request_id, str(request_id)}:
        raise RadarProtocolError("Radar MCP response id did not match the request")
    if payload.get("error"):
        error = payload["error"]
        message = error.get("message") if isinstance(error, dict) else str(error)
        raise RadarProtocolError(f"Radar MCP error: {str(message)[:400]}")
    result = payload.get("result")
    if not isinstance(result, dict):
        raise RadarProtocolError("Radar MCP response did not contain an object result")
    return result


async def _post(client: httpx.AsyncClient, endpoint: str, payload: dict[str, Any], headers: dict[str, str]) -> httpx.Response:
    try:
        return await client.post(endpoint, headers=headers, json=payload)
    except httpx.HTTPError as exc:
        raise RadarUnavailable(f"Radar unavailable: {type(exc).__name__}") from exc


async def query(
    endpoint: str,
    tool: str,
    arguments: dict[str, Any],
    *,
    timeout: float = 10.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    validate_read_tool(tool, arguments)
    endpoint = _endpoint(endpoint)
    base_headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "User-Agent": "hermes-control-plane/radar-read-adapter",
    }
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, transport=transport) as client:
        initialize_id = 1
        initialize = await _post(
            client,
            endpoint,
            {
                "jsonrpc": "2.0",
                "id": initialize_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "hermes-control-plane", "version": "0.5.11"},
                },
            },
            base_headers,
        )
        initialized = _unwrap(_response_json(initialize), initialize_id)
        protocol_version = str(initialized.get("protocolVersion") or MCP_PROTOCOL_VERSION)
        session_id = initialize.headers.get("Mcp-Session-Id")
        session_headers = dict(base_headers)
        session_headers["MCP-Protocol-Version"] = protocol_version
        if session_id:
            session_headers["Mcp-Session-Id"] = session_id

        notification = await _post(
            client,
            endpoint,
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            session_headers,
        )
        if notification.status_code >= 400:
            _response_json(notification)

        call_id = 2
        response = await _post(
            client,
            endpoint,
            {
                "jsonrpc": "2.0",
                "id": call_id,
                "method": "tools/call",
                "params": {"name": tool, "arguments": arguments},
            },
            session_headers,
        )
        result = _unwrap(_response_json(response), call_id)
        if result.get("isError") is True:
            raise RadarProtocolError("Radar read tool reported an error")
        return {
            "tool": tool,
            "protocol_version": protocol_version,
            "server_info": redact(initialized.get("serverInfo") or {}),
            "result": redact(result),
        }


async def health(
    endpoint: str,
    *,
    timeout: float = 5.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    endpoint = _endpoint(endpoint)
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "User-Agent": "hermes-control-plane/radar-health",
    }
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, transport=transport) as client:
        response = await _post(
            client,
            endpoint,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "hermes-control-plane-health", "version": "0.5.11"},
                },
            },
            headers,
        )
        initialized = _unwrap(_response_json(response), 1)
        return {
            "ok": True,
            "protocol_version": str(initialized.get("protocolVersion") or MCP_PROTOCOL_VERSION),
            "server_info": redact(initialized.get("serverInfo") or {}),
            "session": bool(response.headers.get("Mcp-Session-Id")),
        }
