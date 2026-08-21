from __future__ import annotations

import os
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
