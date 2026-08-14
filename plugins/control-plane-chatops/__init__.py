"""Hermes Bot -> Control Plane ChatOps tools.

Fail closed: mutating tools are available only in an interactive Telegram session
for an allow-listed numeric Telegram user. The plugin holds only a Control Plane
service token; Kubernetes/Helm credentials stay inside the broker boundary.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

_BASE_URL = os.getenv("HERMES_CONTROL_PLANE_URL", "http://control-plane:8800").rstrip("/")
_BOT_TOKEN = os.getenv("HERMES_BOT_SERVICE_TOKEN", "")
_BOT_USERS = frozenset(
    x.strip() for x in os.getenv("HERMES_CONTROL_PLANE_BOT_USERS", "").replace(",", "\n").splitlines()
    if x.strip().isdigit()
)


def _json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _error(message: str) -> str:
    return _json({"error": message})


def _session_env(name: str, default: str = "") -> str:
    try:
        from gateway.session_context import get_session_env
        return str(get_session_env(name, default) or "")
    except Exception:
        return str(os.getenv(name, default) or "")


def _truthy(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _context_problem() -> str | None:
    if not _BOT_TOKEN:
        return "Hermes Control Plane bot service token is unavailable."
    if _session_env("HERMES_SESSION_PLATFORM") != "telegram":
        return "Kubernetes/Helm mutation is allowed only from the Hermes Telegram bot."
    if _truthy(_session_env("HERMES_CRON_SESSION")):
        return "Kubernetes/Helm mutation is not allowed from cron/background sessions."
    user = _session_env("HERMES_SESSION_USER_ID")
    session = _session_env("HERMES_SESSION_KEY")
    if not user.isdigit() or not session:
        return "Kubernetes/Helm mutation requires a numeric Telegram user and interactive session."
    if user not in _BOT_USERS:
        return "This Telegram user is not authorized for Hermes Control Plane mutation."
    return None


def _actor() -> str:
    return f"telegram:{_session_env('HERMES_SESSION_USER_ID')}"


def _call(method: str, path: str, payload: dict[str, Any] | None = None, *, auth: bool = True, timeout: int = 90) -> dict[str, Any] | list[Any]:
    headers = {"Accept": "application/json"}
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    if auth:
        headers["Authorization"] = f"Bearer {_BOT_TOKEN}"
    request = urllib.request.Request(_BASE_URL + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return json.loads(raw or b"null")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            body = json.loads(raw)
            detail = body.get("detail", body) if isinstance(body, dict) else body
        except json.JSONDecodeError:
            detail = raw or exc.reason
        return {"error": str(detail), "status_code": exc.code}
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        return {"error": f"Control Plane unavailable: {type(exc).__name__}."}


def _guarded() -> str | None:
    problem = _context_problem()
    return _error(problem) if problem else None


def _list_targets(payload: dict[str, Any] | None = None, **_: Any) -> str:
    if blocked := _guarded():
        return blocked
    rows = _call("GET", "/v1/targets", auth=False, timeout=20)
    if isinstance(rows, dict) and rows.get("error"):
        return _json(rows)
    return _json([x for x in rows if isinstance(x, dict) and x.get("kind") == "kubernetes"])


def _get_changeset(payload: dict[str, Any], **_: Any) -> str:
    if blocked := _guarded():
        return blocked
    cid = str(payload.get("changeset_id", "")).strip()
    if not cid:
        return _error("changeset_id is required")
    return _json(_call("GET", f"/v1/changesets/{cid}", auth=False, timeout=20))


def _create_and_preview(body: dict[str, Any]) -> str:
    created = _call("POST", "/v1/changesets", body)
    if isinstance(created, dict) and created.get("error"):
        return _json(created)
    cid = str(created.get("id", ""))
    if not cid:
        return _error("Control Plane returned an incomplete ChangeSet")
    previewed = _call("POST", f"/v1/changesets/{cid}/preview-live", {})
    return _json(previewed)


def _plan_kubernetes(payload: dict[str, Any], **_: Any) -> str:
    if blocked := _guarded():
        return blocked
    operation = str(payload.get("operation", "kubernetes.manifest.apply"))
    if operation not in {"kubernetes.manifest.apply", "kubernetes.manifest.delete"}:
        return _error("operation must be kubernetes.manifest.apply or kubernetes.manifest.delete")
    target_id = str(payload.get("target_id", "")).strip()
    manifest = str(payload.get("manifest", "")).strip()
    namespace = str(payload.get("namespace", "default")).strip() or "default"
    if not target_id or not manifest:
        return _error("target_id and manifest are required")
    return _create_and_preview({
        "operation": operation,
        "adapter": "kubernetes",
        "target_id": target_id,
        "requested_by": _actor(),
        "source_channel": "hermes-bot",
        "parameters": {"namespace": namespace, "manifest": manifest},
    })


def _plan_helm(payload: dict[str, Any], **_: Any) -> str:
    if blocked := _guarded():
        return blocked
    operation = str(payload.get("operation", "helm.install"))
    if operation not in {"helm.install", "helm.upgrade", "helm.rollback", "helm.uninstall"}:
        return _error("unsupported Helm operation")
    target_id = str(payload.get("target_id", "")).strip()
    release = str(payload.get("release", "")).strip()
    namespace = str(payload.get("namespace", "default")).strip() or "default"
    if not target_id or not release:
        return _error("target_id and release are required")
    params: dict[str, Any] = {"release": release, "namespace": namespace}
    if operation in {"helm.install", "helm.upgrade"}:
        chart = str(payload.get("chart", "")).strip()
        if not chart:
            return _error("chart is required for Helm install/upgrade")
        params.update({
            "chart": chart,
            "version": payload.get("version") or None,
            "values_yaml": str(payload.get("values_yaml", "")),
            "create_namespace": bool(payload.get("create_namespace", True)),
        })
    elif operation == "helm.rollback":
        revision = int(payload.get("revision", 0) or 0)
        if revision < 1:
            return _error("revision must be >= 1 for Helm rollback")
        params["revision"] = revision
    return _create_and_preview({
        "operation": operation,
        "adapter": "helm",
        "target_id": target_id,
        "requested_by": _actor(),
        "source_channel": "hermes-bot",
        "parameters": params,
    })


def _request_approval(payload: dict[str, Any], **_: Any) -> str:
    if blocked := _guarded():
        return blocked
    cid = str(payload.get("changeset_id", "")).strip()
    if not cid:
        return _error("changeset_id is required")
    return _json(_call("POST", f"/v1/changesets/{cid}/request-approval", {}))


def _execute(payload: dict[str, Any], **_: Any) -> str:
    if blocked := _guarded():
        return blocked
    cid = str(payload.get("changeset_id", "")).strip()
    if not cid:
        return _error("changeset_id is required")
    return _json(_call("POST", f"/v1/changesets/{cid}/execute", {"actor": _actor()}, timeout=360))


def _plan_rollback(payload: dict[str, Any], **_: Any) -> str:
    if blocked := _guarded():
        return blocked
    source_id = str(payload.get("source_changeset_id", "")).strip()
    if not source_id:
        return _error("source_changeset_id is required")
    created = _call("POST", f"/v1/changesets/{source_id}/rollback-plan", {
        "requested_by": _actor(),
        "source_channel": "hermes-bot",
        "ttl_seconds": 900,
    })
    if isinstance(created, dict) and created.get("error"):
        return _json(created)
    cid = str(created.get("id", ""))
    if not cid:
        return _error("Control Plane returned an incomplete rollback ChangeSet")
    return _json(_call("POST", f"/v1/changesets/{cid}/preview-live", {}))


def _tool(name: str, description: str, handler, properties: dict[str, Any], required: list[str]):
    return dict(
        name=name,
        description=description,
        handler=handler,
        schema={
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False,
            },
        },
    )


def register(context):
    definitions = [
        _tool("hcp_list_targets", "List Kubernetes targets available to Hermes Bot.", _list_targets, {}, []),
        _tool("hcp_get_changeset", "Inspect a Hermes Control Plane ChangeSet and its preview/execution state.", _get_changeset, {"changeset_id": {"type": "string"}}, ["changeset_id"]),
        _tool("hcp_plan_kubernetes", "Create and live-preview a bot-only Kubernetes apply/delete ChangeSet. This does not execute it.", _plan_kubernetes, {
            "operation": {"type": "string", "enum": ["kubernetes.manifest.apply", "kubernetes.manifest.delete"]},
            "target_id": {"type": "string"}, "namespace": {"type": "string"}, "manifest": {"type": "string"},
        }, ["operation", "target_id", "manifest"]),
        _tool("hcp_plan_helm", "Create and live-preview a bot-only Helm ChangeSet. This does not execute it.", _plan_helm, {
            "operation": {"type": "string", "enum": ["helm.install", "helm.upgrade", "helm.rollback", "helm.uninstall"]},
            "target_id": {"type": "string"}, "release": {"type": "string"}, "namespace": {"type": "string"},
            "chart": {"type": "string"}, "version": {"type": "string"}, "values_yaml": {"type": "string"},
            "create_namespace": {"type": "boolean"}, "revision": {"type": "integer"},
        }, ["operation", "target_id", "release"]),
        _tool("hcp_request_approval", "Request separate Approval Bot authorization for a PREVIEWED ChangeSet.", _request_approval, {"changeset_id": {"type": "string"}}, ["changeset_id"]),
        _tool("hcp_execute_changeset", "Execute an already approved exact-hash ChangeSet. This tool cannot approve changes.", _execute, {"changeset_id": {"type": "string"}}, ["changeset_id"]),
        _tool("hcp_plan_rollback", "Create and live-preview a new rollback ChangeSet from an executed ChangeSet.", _plan_rollback, {"source_changeset_id": {"type": "string"}}, ["source_changeset_id"]),
    ]
    for definition in definitions:
        context.register_tool(toolset="control-plane-chatops", **definition)
