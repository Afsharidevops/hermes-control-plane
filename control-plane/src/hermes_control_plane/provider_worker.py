from __future__ import annotations

import json
import os
import re
from typing import Any

import httpx
from fastapi import HTTPException

BASE_URL = os.getenv("HERMES_PROVIDER_WORKER_URL", "http://node-agent:8810").rstrip("/")
TOKEN = os.getenv("HERMES_PROVIDER_WORKER_TOKEN", "")
TIMEOUT = float(os.getenv("HERMES_PROVIDER_WORKER_TIMEOUT_SECONDS", "1900"))


def _headers() -> dict[str, str]:
    if not TOKEN:
        raise HTTPException(status_code=503, detail="provider worker token is not configured")
    return {"Authorization": f"Bearer {TOKEN}"}


CAPACITY_TIMEOUT = float(os.getenv("HERMES_CAPACITY_WORKER_TIMEOUT_SECONDS", "60"))
CAPACITY_MAX_TIMEOUT = 60.0
CAPACITY_MAX_RESPONSE_BYTES = 1_048_576
VM_INVENTORY_TIMEOUT = float(os.getenv("HERMES_VM_INVENTORY_WORKER_TIMEOUT_SECONDS", "60"))
VM_INVENTORY_MAX_TIMEOUT = 60.0
VM_INVENTORY_MAX_RESPONSE_BYTES = 1_048_576


async def post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.post(f"{BASE_URL}{path}", headers=_headers(), json=payload)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"provider worker unavailable: {type(exc).__name__}") from exc
    try:
        body = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="provider worker returned non-JSON response") from exc
    if response.status_code >= 400:
        detail = body.get("detail") if isinstance(body, dict) else None
        raise HTTPException(status_code=response.status_code, detail=detail or "provider worker request failed")
    if not isinstance(body, dict):
        raise HTTPException(status_code=502, detail="provider worker returned invalid response")
    return body


async def _bounded_refresh(path: str, payload: dict[str, Any], *, timeout: float, max_timeout: float, max_response_bytes: int, failure_prefix: str) -> dict[str, Any]:
    if not 0 < timeout <= max_timeout:
        raise HTTPException(status_code=503, detail=f"{failure_prefix} worker timeout is outside the fixed bound")
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            async with client.stream(
                "POST",
                f"{BASE_URL}{path}",
                headers=_headers(),
                json=payload,
            ) as response:
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > max_response_bytes:
                        raise HTTPException(status_code=502, detail=f"{failure_prefix} worker response exceeds the bounded limit")
                    chunks.append(chunk)
                raw = b"".join(chunks)
                status_code = response.status_code
    except HTTPException:
        raise
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"{failure_prefix} worker unavailable: {type(exc).__name__}") from exc
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=502, detail=f"{failure_prefix} worker returned non-JSON response") from exc
    if status_code >= 400:
        raise HTTPException(status_code=502, detail=f"{failure_prefix} worker collection failed")
    if not isinstance(body, dict):
        raise HTTPException(status_code=502, detail=f"{failure_prefix} worker returned invalid response")
    return body


async def capacity_refresh(provider_snapshot: dict[str, Any]) -> dict[str, Any]:
    return await _bounded_refresh(
        "/v1/capacity/refresh",
        {"provider_snapshot": provider_snapshot},
        timeout=CAPACITY_TIMEOUT,
        max_timeout=CAPACITY_MAX_TIMEOUT,
        max_response_bytes=CAPACITY_MAX_RESPONSE_BYTES,
        failure_prefix="capacity",
    )


async def vm_inventory_refresh(provider_snapshot: dict[str, Any]) -> dict[str, Any]:
    return await _bounded_refresh(
        "/v1/vm/inventory/refresh",
        {"provider_snapshot": provider_snapshot},
        timeout=VM_INVENTORY_TIMEOUT,
        max_timeout=VM_INVENTORY_MAX_TIMEOUT,
        max_response_bytes=VM_INVENTORY_MAX_RESPONSE_BYTES,
        failure_prefix="vm inventory",
    )


HOST_OBSERVER_URL = os.getenv("HERMES_HOST_OBSERVER_URL", "").rstrip("/")
HOST_OBSERVER_TOKEN = os.getenv("HERMES_HOST_OBSERVER_TOKEN", "")
HOST_OBSERVER_TIMEOUT = float(os.getenv("HERMES_HOST_OBSERVER_TIMEOUT_SECONDS", "10"))
HOST_OBSERVER_MAX_TIMEOUT = 30.0
HOST_OBSERVER_SERVICE_RE = re.compile(r"^(?:host-observer|[a-z0-9](?:[-a-z0-9]*[a-z0-9])?-host-observer)$")


def _host_observer_endpoint() -> str:
    if not HOST_OBSERVER_TOKEN:
        raise HTTPException(status_code=503, detail="host observer token is not configured")
    try:
        parsed = httpx.URL(HOST_OBSERVER_URL)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="host observer endpoint is invalid") from exc
    if (
        parsed.scheme != "http"
        or not parsed.host
        or not HOST_OBSERVER_SERVICE_RE.fullmatch(parsed.host)
        or parsed.port != 8811
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise HTTPException(status_code=503, detail="host observer endpoint is not the fixed in-cluster service")
    if not 0 < HOST_OBSERVER_TIMEOUT <= HOST_OBSERVER_MAX_TIMEOUT:
        raise HTTPException(status_code=503, detail="host observer timeout is outside the fixed bound")
    return "http://host-observer:8811/v1/collectors/host-network"


async def collect_host_network() -> dict[str, Any]:
    endpoint = _host_observer_endpoint()
    try:
        async with httpx.AsyncClient(timeout=HOST_OBSERVER_TIMEOUT, follow_redirects=False) as client:
            response = await client.post(
                endpoint,
                headers={"Authorization": f"Bearer {HOST_OBSERVER_TOKEN}"},
                json={},
            )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"host observer unavailable: {type(exc).__name__}") from exc
    if len(response.content) > 128_000:
        raise HTTPException(status_code=502, detail="host observer response exceeds 128 KiB")
    try:
        body = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="host observer returned non-JSON response") from exc
    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail="host observer collection failed")
    if not isinstance(body, dict):
        raise HTTPException(status_code=502, detail="host observer returned invalid response")
    return body
