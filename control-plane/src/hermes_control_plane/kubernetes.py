from __future__ import annotations

import os
from typing import Any

import httpx
from fastapi import HTTPException


BASE_URL = os.getenv("HERMES_KUBERNETES_BROKER_URL", "http://kubernetes-broker:8830").rstrip("/")
TOKEN = os.getenv("HERMES_KUBERNETES_BROKER_TOKEN", "")
TIMEOUT = float(os.getenv("HERMES_KUBERNETES_BROKER_TIMEOUT", "180"))


def _headers() -> dict[str, str]:
    if not TOKEN:
        raise HTTPException(503, "HERMES_KUBERNETES_BROKER_TOKEN is not configured")
    return {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}


def _response_detail(response: httpx.Response) -> Any:
    try:
        detail: Any = response.json()
    except ValueError:
        return response.text[:2000]
    while isinstance(detail, dict) and "detail" in detail and len(detail) == 1:
        detail = detail["detail"]
    return detail


async def post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.post(f"{BASE_URL}{path}", headers=_headers(), json=payload)
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"Kubernetes Broker unavailable: {type(exc).__name__}") from exc
    if response.status_code >= 400:
        raise HTTPException(
            response.status_code if response.status_code < 500 else 502,
            _response_detail(response),
        )
    return response.json()


async def health() -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(f"{BASE_URL}/health")
            return response.json() if response.status_code < 500 else {"ok": False, "status": response.status_code}
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__}
