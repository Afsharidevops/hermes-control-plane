from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from starlette.responses import StreamingResponse
from pydantic import BaseModel

VERSION = "0.5.10-rc.1"
STATE_FILE = Path(os.getenv("ROUTER_GATEWAY_STATE_FILE", "/data/router.json"))
ADMIN_TOKEN = os.getenv("ROUTER_GATEWAY_ADMIN_TOKEN", "")
DEFAULT_PROVIDER = os.getenv("HERMES_ROUTER_PROVIDER", "nine-router")

MODEL_ALIASES = {
    "nine-router": {
        "hermes/observe": "ai",
        "hermes/fast": "combo-fast",
        "hermes/standard": "combo-standard",
        "hermes/strong": "combo-strong",
        "hermes/coding": "combo-strong",
        "hermes/vision": "combo-strong",
    },
    "omniroute": {
        "hermes/observe": "auto/best-chat",
        "hermes/fast": "auto/best-fast",
        "hermes/standard": "auto/best-chat",
        "hermes/strong": "auto/best-reasoning",
        "hermes/coding": "auto/best-coding",
        "hermes/vision": "auto/best-vision",
    },
}

PROVIDERS = {
    "nine-router": {
        "base_url": os.getenv("NINE_ROUTER_BASE_URL", "http://nine-router:20128/v1"),
        "health_url": os.getenv("NINE_ROUTER_HEALTH_URL", "http://nine-router:20128/api/health"),
        "api_key": os.getenv("NINE_ROUTER_API_KEY", ""),
    },
    "omniroute": {
        "base_url": os.getenv("OMNIROUTE_BASE_URL", "http://omniroute:20129/v1"),
        "health_url": os.getenv("OMNIROUTE_HEALTH_URL", "http://omniroute:20128/api/monitoring/health"),
        "api_key": os.getenv("OMNIROUTE_UPSTREAM_API_KEY", ""),
    },
}

app = FastAPI(title="Hermes Router Gateway", version=VERSION)


def _load_active() -> str:
    try:
        data = json.loads(STATE_FILE.read_text())
        provider = data.get("active_provider")
        if provider in PROVIDERS:
            return provider
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    return DEFAULT_PROVIDER if DEFAULT_PROVIDER in PROVIDERS else "nine-router"


def _save_active(provider: str) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps({"active_provider": provider}, sort_keys=True))
    tmp.replace(STATE_FILE)


def _require_admin(authorization: str | None) -> None:
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=503, detail="ROUTER_GATEWAY_ADMIN_TOKEN is not configured")
    if authorization != f"Bearer {ADMIN_TOKEN}":
        raise HTTPException(status_code=401, detail="invalid admin token")


class RouterSelection(BaseModel):
    provider: str


@app.on_event("startup")
def startup() -> None:
    if not STATE_FILE.exists():
        _save_active(_load_active())


@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True, "service": "hermes-router-gateway", "version": VERSION, "active_provider": _load_active()}


@app.get("/management/providers")
async def providers(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    active = _load_active()
    result: dict[str, Any] = {}
    async with httpx.AsyncClient(timeout=3.0) as client:
        for name, cfg in PROVIDERS.items():
            healthy = False
            status_code = None
            try:
                res = await client.get(cfg["health_url"])
                status_code = res.status_code
                healthy = 200 <= res.status_code < 300
            except httpx.HTTPError:
                pass
            result[name] = {
                "active": name == active,
                "healthy": healthy,
                "health_status": status_code,
                "base_url": cfg["base_url"],
                "credential_configured": bool(cfg["api_key"]),
            }
    return {"active_provider": active, "providers": result}


@app.put("/management/router")
def select_router(payload: RouterSelection, authorization: str | None = Header(default=None)) -> dict[str, str]:
    _require_admin(authorization)
    if payload.provider not in PROVIDERS:
        raise HTTPException(status_code=400, detail=f"unknown provider: {payload.provider}")
    _save_active(payload.provider)
    return {"active_provider": payload.provider}


@app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def proxy_v1(path: str, request: Request) -> Response:
    provider = _load_active()
    cfg = PROVIDERS[provider]
    target = f"{cfg['base_url'].rstrip('/')}/{path}"
    headers = dict(request.headers)
    for header in ("host", "content-length", "connection", "transfer-encoding"):
        headers.pop(header, None)
    if cfg["api_key"]:
        headers["authorization"] = f"Bearer {cfg['api_key']}"
    body = await request.body()
    # Smart Router uses stable neutral model aliases. Translate only known aliases;
    # explicit provider model IDs pass through unchanged.
    content_type = request.headers.get("content-type", "")
    if body and "application/json" in content_type:
        try:
            payload = json.loads(body)
            model = payload.get("model") if isinstance(payload, dict) else None
            if isinstance(model, str) and model in MODEL_ALIASES[provider]:
                payload["model"] = MODEL_ALIASES[provider][model]
                body = json.dumps(payload, separators=(",", ":")).encode()
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
    client = httpx.AsyncClient(timeout=httpx.Timeout(600.0, connect=10.0))
    try:
        outgoing = client.build_request(
            request.method,
            target,
            params=request.query_params,
            headers=headers,
            content=body,
        )
        upstream = await client.send(outgoing, stream=True)
    except httpx.HTTPError as exc:
        await client.aclose()
        raise HTTPException(status_code=502, detail=f"active provider {provider} unavailable") from exc

    excluded = {"content-length", "transfer-encoding", "connection", "content-encoding"}
    response_headers = {k: v for k, v in upstream.headers.items() if k.lower() not in excluded}
    response_headers["x-hermes-router-provider"] = provider

    async def body_stream():
        try:
            async for chunk in upstream.aiter_raw():
                yield chunk
        finally:
            await upstream.aclose()
            await client.aclose()

    return StreamingResponse(
        body_stream(),
        status_code=upstream.status_code,
        headers=response_headers,
        media_type=None,
    )
