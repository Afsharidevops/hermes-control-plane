from __future__ import annotations

import json
import os
import time
import uuid
from contextlib import asynccontextmanager, closing
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse

from . import db
from .canonical import canonical_json, sha256_hex
from . import kubernetes as kubernetes_broker
from .tickets import issue_ticket
from .models import (
    ApprovalDecision,
    ChangeSetCreate,
    CredentialRefCreate,
    CredentialRefUpdate,
    EnvironmentCreate,
    EnvironmentUpdate,
    ExecuteDecision,
    IntegrationCreate,
    IntegrationUpdate,
    PreviewCreate,
    RejectDecision,
    RollbackPlanCreate,
    TargetCreate,
    TargetUpdate,
)
from .risk import approval_required, classify

VERSION = "0.5.10-beta.1"
STATIC_DIR = Path(__file__).resolve().parent / "static"
TERMINAL_CHANGESET_STATES = {
    "REJECTED", "CANCELLED", "EXPIRED", "EXECUTED", "FAILED",
    "POLICY_DENIED", "PREVIEW_FAILED",
}
INFRA_MUTATION_ADAPTERS = {"kubernetes", "helm"}
BOT_SOURCE_CHANNELS = {"telegram", "hermes-bot", "api"}


def _is_infra_mutation(adapter: str, operation: str) -> bool:
    """Keep read-only Kubernetes/Helm inspection available to admin/UI, but mutations bot-only."""
    return adapter in INFRA_MUTATION_ADAPTERS and classify(operation) != "READ"


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
    yield


app = FastAPI(
    title="Hermes Control Plane API",
    version=VERSION,
    description="Kubernetes + Helm beta vertical slice for Hermes Control Plane",
    lifespan=lifespan,
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _admin_token() -> str:
    return os.getenv("HERMES_CONTROL_ADMIN_TOKEN", "")


def _bot_token() -> str:
    return os.getenv("HERMES_BOT_SERVICE_TOKEN", "")


def _approval_bot_token() -> str:
    return os.getenv("HERMES_APPROVAL_BOT_TOKEN", "")


def _require_token(authorization: str | None, token: str, label: str) -> None:
    if not token:
        raise HTTPException(status_code=503, detail=f"{label} is not configured")
    if authorization != f"Bearer {token}":
        raise HTTPException(status_code=401, detail=f"invalid {label.lower()}")


def _require_admin(authorization: str | None) -> None:
    _require_token(authorization, _admin_token(), "HERMES_CONTROL_ADMIN_TOKEN")


def _require_bot(authorization: str | None) -> None:
    if authorization == f"Bearer {_admin_token()}":
        raise HTTPException(status_code=403, detail="Kubernetes and Helm mutation is bot-only")
    _require_token(authorization, _bot_token(), "HERMES_BOT_SERVICE_TOKEN")


def _require_approval_bot(authorization: str | None) -> None:
    if authorization in {f"Bearer {_admin_token()}", f"Bearer {_bot_token()}"}:
        raise HTTPException(status_code=403, detail="approval is restricted to the separate Approval Bot identity")
    _require_token(authorization, _approval_bot_token(), "HERMES_APPROVAL_BOT_TOKEN")


def _require_bot_origin(source_channel: str) -> None:
    if source_channel not in BOT_SOURCE_CHANNELS:
        raise HTTPException(
            status_code=403,
            detail="Kubernetes and Helm mutation plans may only originate from Hermes Bot",
        )


def _require_infra_actor(row: Any, authorization: str | None) -> None:
    if _is_infra_mutation(row["adapter"], row["operation"]):
        _require_bot(authorization)
    else:
        _require_admin(authorization)


def _row_json(row: Any, json_fields: dict[str, str]) -> dict[str, Any]:
    item = dict(row)
    for source, dest in json_fields.items():
        raw = item.pop(source, None)
        item[dest] = json.loads(raw or "{}")
    return item


def _get_environment(conn, environment_id: str):
    row = conn.execute("SELECT * FROM environments WHERE id=?", (environment_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="environment not found")
    return row


def _get_credential_ref(conn, credential_ref: str | None):
    if not credential_ref:
        return None
    row = conn.execute("SELECT * FROM credential_refs WHERE id=?", (credential_ref,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="credential reference not found")
    if row["status"] == "revoked":
        raise HTTPException(status_code=409, detail="credential reference is revoked")
    return row


def _integration_dict(row: Any) -> dict[str, Any]:
    item = _row_json(row, {"labels_json": "labels", "allowed_scope_json": "allowed_scope"})
    item.pop("environment", None)  # legacy alpha.1 compatibility column
    return item


def _target_dict(row: Any) -> dict[str, Any]:
    return _row_json(row, {"scope_json": "scope", "labels_json": "labels"})


def _credential_snapshot(conn, credential_ref: str | None) -> dict[str, Any] | None:
    if not credential_ref:
        return None
    row = _get_credential_ref(conn, credential_ref)
    return {
        "id": row["id"],
        "kind": row["kind"],
        "provider": row["provider"],
        "status": row["status"],
        "metadata": json.loads(row["metadata_json"] or "{}"),
        "updated_at": row["updated_at"],
    }


def _target_snapshot(conn, target_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="target not found")
    target = _target_dict(row)
    snapshot = {
        "id": target["id"],
        "name": target["name"],
        "kind": target["kind"],
        "environment_id": target["environment_id"],
        "integration_id": target["integration_id"],
        "credential_ref": target["credential_ref"],
        "connection_mode": target["connection_mode"],
        "address": target["address"],
        "scope": target["scope"],
        "status": target["status"],
        "credential_snapshot": _credential_snapshot(conn, target["credential_ref"]),
    }
    snapshot["snapshot_hash"] = sha256_hex(snapshot)
    return snapshot


def _changeset_dict(row: Any) -> dict[str, Any]:
    item = dict(row)
    item["parameters"] = json.loads(item.pop("parameters_json") or "{}")
    item["plan"] = json.loads(item.pop("plan_json") or "{}")
    item["preview"] = json.loads(item.pop("preview_json") or "null")
    item["execution"] = json.loads(item.pop("execution_json", None) or "null")
    item["approval_required"] = bool(item["approval_required"])
    enabled = os.getenv("HERMES_EXECUTION_ENABLED", "false").lower() == "true"
    execution_state_ready = (
        item["state"] == "APPROVED"
        or (
            item["state"] == "PREVIEWED"
            and not item["approval_required"]
        )
    )
    item["executable"] = (
        enabled
        and item["adapter"] in {"kubernetes", "helm"}
        and execution_state_ready
    )
    item["execution_note"] = "beta.1 execution requires live preview, approval when required, target snapshot match, and a signed one-time broker ticket"
    return item


def _changeset(conn, changeset_id: str):
    row = conn.execute("SELECT * FROM changesets WHERE id=?", (changeset_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="changeset not found")
    if row["expires_at"] and int(row["expires_at"]) < int(time.time()) and row["state"] not in TERMINAL_CHANGESET_STATES:
        conn.execute("UPDATE changesets SET state='EXPIRED', updated_at=? WHERE id=?", (int(time.time()), changeset_id))
        db.audit(conn, "changeset.expired", "system", "changeset", changeset_id, {"plan_hash": row["plan_hash"]})
        conn.commit()
        row = conn.execute("SELECT * FROM changesets WHERE id=?", (changeset_id,)).fetchone()
    return row


@app.get("/")
def root() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/ui")
def ui() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True, "service": "hermes-control-plane", "version": VERSION}


@app.get("/v1/system")
def system() -> dict[str, Any]:
    with closing(db.connect()) as conn:
        counts = {
            "environments": conn.execute("SELECT COUNT(*) FROM environments").fetchone()[0],
            "integrations": conn.execute("SELECT COUNT(*) FROM integrations").fetchone()[0],
            "targets": conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0],
            "credential_refs": conn.execute("SELECT COUNT(*) FROM credential_refs").fetchone()[0],
            "changesets": conn.execute("SELECT COUNT(*) FROM changesets").fetchone()[0],
        }
    return {
        "name": "Hermes Control Plane",
        "version": VERSION,
        "stage": "beta-dev",
        "runtime": os.getenv("HERMES_RUNTIME", "docker"),
        "capabilities": ["integration-registry", "target-registry", "credential-references", "changeset-planning", "risk-engine", "approval-binding", "audit", "kubernetes-discovery", "kubernetes-server-dry-run", "kubernetes-guarded-delete", "kubernetes-rollback", "kubernetes-rollout-verification", "helm-server-dry-run", "helm-rollback", "signed-execution-tickets"],
        "execution_enabled": os.getenv("HERMES_EXECUTION_ENABLED", "false").lower() == "true",
        "mutation_control": {
            "kubernetes_helm": "bot-only",
            "approval": "approval-bot-only",
            "ui": "configuration-and-observability",
        },
        "counts": counts,
    }


@app.get("/v1/environments")
def list_environments() -> list[dict[str, Any]]:
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM environments ORDER BY name").fetchall()
    return [_row_json(row, {"labels_json": "labels"}) for row in rows]


@app.post("/v1/environments", status_code=201)
def create_environment(payload: EnvironmentCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    slug = db.slugify(payload.slug or payload.name)
    env_id = f"env_{uuid.uuid4().hex[:16]}"
    now = int(time.time())
    with closing(db.connect()) as conn:
        try:
            conn.execute(
                "INSERT INTO environments (id,name,slug,risk_level,labels_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
                (env_id, payload.name, slug, payload.risk_level, json.dumps(payload.labels, sort_keys=True), now, now),
            )
            db.audit(conn, "environment.created", "admin", "environment", env_id, {"name": payload.name, "risk_level": payload.risk_level})
            conn.commit()
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise HTTPException(status_code=409, detail="environment name or slug already exists") from exc
            raise
    return {"id": env_id, "name": payload.name, "slug": slug, "risk_level": payload.risk_level, "labels": payload.labels, "created_at": now, "updated_at": now}


@app.patch("/v1/environments/{environment_id}")
def update_environment(environment_id: str, payload: EnvironmentUpdate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="no fields supplied")
    with closing(db.connect()) as conn:
        _get_environment(conn, environment_id)
        if "labels" in updates:
            updates["labels_json"] = json.dumps(updates.pop("labels"), sort_keys=True)
        updates["updated_at"] = int(time.time())
        fields = list(updates)
        conn.execute(f"UPDATE environments SET {', '.join(f'{f}=?' for f in fields)} WHERE id=?", (*[updates[f] for f in fields], environment_id))
        db.audit(conn, "environment.updated", "admin", "environment", environment_id, {"fields": fields})
        conn.commit()
        row = conn.execute("SELECT * FROM environments WHERE id=?", (environment_id,)).fetchone()
    return _row_json(row, {"labels_json": "labels"})


@app.delete("/v1/environments/{environment_id}", status_code=204)
def delete_environment(environment_id: str, authorization: str | None = Header(default=None)) -> None:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        if conn.execute("SELECT 1 FROM integrations WHERE environment_id=? LIMIT 1", (environment_id,)).fetchone() or conn.execute("SELECT 1 FROM targets WHERE environment_id=? LIMIT 1", (environment_id,)).fetchone():
            raise HTTPException(status_code=409, detail="environment is in use")
        cur = conn.execute("DELETE FROM environments WHERE id=?", (environment_id,))
        if not cur.rowcount:
            raise HTTPException(status_code=404, detail="environment not found")
        db.audit(conn, "environment.deleted", "admin", "environment", environment_id)
        conn.commit()


@app.get("/v1/credential-refs")
def list_credential_refs() -> list[dict[str, Any]]:
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM credential_refs ORDER BY name").fetchall()
    return [_row_json(row, {"metadata_json": "metadata"}) for row in rows]


@app.post("/v1/credential-refs", status_code=201)
def create_credential_ref(payload: CredentialRefCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    cred_id = f"cred_{uuid.uuid4().hex[:16]}"
    now = int(time.time())
    with closing(db.connect()) as conn:
        try:
            conn.execute(
                "INSERT INTO credential_refs (id,name,kind,provider,status,metadata_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (cred_id, payload.name, payload.kind, payload.provider, "configured", json.dumps(payload.metadata, sort_keys=True), now, now),
            )
            db.audit(conn, "credential_ref.created", "admin", "credential_ref", cred_id, {"kind": payload.kind, "provider": payload.provider})
            conn.commit()
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise HTTPException(status_code=409, detail="credential reference name already exists") from exc
            raise
    return {"id": cred_id, **payload.model_dump(), "status": "configured", "created_at": now, "updated_at": now, "secret_material_stored": False}


@app.patch("/v1/credential-refs/{credential_id}")
def update_credential_ref(credential_id: str, payload: CredentialRefUpdate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="no fields supplied")
    with closing(db.connect()) as conn:
        if not conn.execute("SELECT 1 FROM credential_refs WHERE id=?", (credential_id,)).fetchone():
            raise HTTPException(status_code=404, detail="credential reference not found")
        if "metadata" in updates:
            updates["metadata_json"] = json.dumps(updates.pop("metadata"), sort_keys=True)
        updates["updated_at"] = int(time.time())
        fields = list(updates)
        conn.execute(f"UPDATE credential_refs SET {', '.join(f'{f}=?' for f in fields)} WHERE id=?", (*[updates[f] for f in fields], credential_id))
        db.audit(conn, "credential_ref.updated", "admin", "credential_ref", credential_id, {"fields": fields})
        conn.commit()
        row = conn.execute("SELECT * FROM credential_refs WHERE id=?", (credential_id,)).fetchone()
    return _row_json(row, {"metadata_json": "metadata"})


@app.delete("/v1/credential-refs/{credential_id}", status_code=204)
def delete_credential_ref(credential_id: str, authorization: str | None = Header(default=None)) -> None:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        if conn.execute("SELECT 1 FROM integrations WHERE credential_ref=? LIMIT 1", (credential_id,)).fetchone() or conn.execute("SELECT 1 FROM targets WHERE credential_ref=? LIMIT 1", (credential_id,)).fetchone():
            raise HTTPException(status_code=409, detail="credential reference is in use")
        cur = conn.execute("DELETE FROM credential_refs WHERE id=?", (credential_id,))
        if not cur.rowcount:
            raise HTTPException(status_code=404, detail="credential reference not found")
        db.audit(conn, "credential_ref.deleted", "admin", "credential_ref", credential_id)
        conn.commit()


@app.get("/v1/integrations")
def list_integrations() -> list[dict[str, Any]]:
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM integrations ORDER BY name").fetchall()
    return [_integration_dict(row) for row in rows]


@app.post("/v1/integrations", status_code=201)
def create_integration(payload: IntegrationCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    now = int(time.time())
    integration_id = f"int_{uuid.uuid4().hex[:16]}"
    with closing(db.connect()) as conn:
        env = _get_environment(conn, payload.environment_id)
        _get_credential_ref(conn, payload.credential_ref)
        try:
            conn.execute(
                """INSERT INTO integrations
                (id,name,kind,environment,endpoint,credential_ref,connection_mode,labels_json,status,created_at,updated_at,environment_id,allowed_scope_json,health_status)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (integration_id, payload.name, payload.kind, env["name"], payload.endpoint, payload.credential_ref, payload.connection_mode,
                 json.dumps(payload.labels, sort_keys=True), "configured", now, now, payload.environment_id,
                 json.dumps(payload.allowed_scope, sort_keys=True), "UNKNOWN"),
            )
            db.audit(conn, "integration.created", "admin", "integration", integration_id, {"kind": payload.kind, "environment_id": payload.environment_id})
            conn.commit()
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise HTTPException(status_code=409, detail="integration name already exists") from exc
            raise
        row = conn.execute("SELECT * FROM integrations WHERE id=?", (integration_id,)).fetchone()
    return _integration_dict(row)


@app.patch("/v1/integrations/{integration_id}")
def update_integration(integration_id: str, payload: IntegrationUpdate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="no fields supplied")
    with closing(db.connect()) as conn:
        if not conn.execute("SELECT 1 FROM integrations WHERE id=?", (integration_id,)).fetchone():
            raise HTTPException(status_code=404, detail="integration not found")
        if "environment_id" in updates:
            env = _get_environment(conn, updates["environment_id"])
            updates["environment"] = env["name"]
        if "credential_ref" in updates:
            _get_credential_ref(conn, updates["credential_ref"])
        if "labels" in updates:
            updates["labels_json"] = json.dumps(updates.pop("labels"), sort_keys=True)
        if "allowed_scope" in updates:
            updates["allowed_scope_json"] = json.dumps(updates.pop("allowed_scope"), sort_keys=True)
        updates["updated_at"] = int(time.time())
        fields = list(updates)
        conn.execute(f"UPDATE integrations SET {', '.join(f'{f}=?' for f in fields)} WHERE id=?", (*[updates[f] for f in fields], integration_id))
        db.audit(conn, "integration.updated", "admin", "integration", integration_id, {"fields": fields})
        conn.commit()
        row = conn.execute("SELECT * FROM integrations WHERE id=?", (integration_id,)).fetchone()
    return _integration_dict(row)


@app.delete("/v1/integrations/{integration_id}", status_code=204)
def delete_integration(integration_id: str, authorization: str | None = Header(default=None)) -> None:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        if conn.execute("SELECT 1 FROM targets WHERE integration_id=? LIMIT 1", (integration_id,)).fetchone():
            raise HTTPException(status_code=409, detail="integration has targets")
        cur = conn.execute("DELETE FROM integrations WHERE id=?", (integration_id,))
        if not cur.rowcount:
            raise HTTPException(status_code=404, detail="integration not found")
        db.audit(conn, "integration.deleted", "admin", "integration", integration_id)
        conn.commit()


@app.post("/v1/integrations/{integration_id}/health")
async def test_integration_health(integration_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        row = conn.execute("SELECT * FROM integrations WHERE id=?", (integration_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="integration not found")
        endpoint = row["endpoint"]
    if not endpoint:
        raise HTTPException(status_code=400, detail="integration has no endpoint")
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=400, detail="health testing currently supports only http/https endpoints")

    status = "UNHEALTHY"
    detail = "connection failed"
    code = None
    try:
        timeout = float(os.getenv("HERMES_HEALTH_TIMEOUT_SECONDS", "5"))
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            response = await client.get(endpoint, headers={"User-Agent": f"hermes-control-plane/{VERSION}"})
            code = response.status_code
            status = "HEALTHY" if 200 <= code < 500 else "UNHEALTHY"
            detail = f"HTTP {code}"
    except Exception as exc:
        detail = f"{type(exc).__name__}: {str(exc)[:240]}"

    now = int(time.time())
    with closing(db.connect()) as conn:
        conn.execute("UPDATE integrations SET health_status=?,last_health_at=?,last_health_detail=?,updated_at=? WHERE id=?", (status, now, detail, now, integration_id))
        db.audit(conn, "integration.health", "admin", "integration", integration_id, {"status": status, "detail": detail, "http_status": code})
        conn.commit()
    return {"integration_id": integration_id, "status": status, "detail": detail, "http_status": code, "tested_at": now, "credential_used": False}


@app.get("/v1/targets")
def list_targets() -> list[dict[str, Any]]:
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM targets ORDER BY name").fetchall()
    return [_target_dict(row) for row in rows]


@app.post("/v1/targets", status_code=201)
def create_target(payload: TargetCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    target_id = f"tgt_{uuid.uuid4().hex[:16]}"
    now = int(time.time())
    with closing(db.connect()) as conn:
        _get_environment(conn, payload.environment_id)
        _get_credential_ref(conn, payload.credential_ref)
        if payload.integration_id and not conn.execute("SELECT 1 FROM integrations WHERE id=?", (payload.integration_id,)).fetchone():
            raise HTTPException(status_code=404, detail="integration not found")
        try:
            conn.execute(
                """INSERT INTO targets
                (id,name,kind,environment_id,integration_id,credential_ref,connection_mode,address,scope_json,labels_json,status,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (target_id, payload.name, payload.kind, payload.environment_id, payload.integration_id, payload.credential_ref,
                 payload.connection_mode, payload.address, json.dumps(payload.scope, sort_keys=True), json.dumps(payload.labels, sort_keys=True),
                 "configured", now, now),
            )
            db.audit(conn, "target.created", "admin", "target", target_id, {"kind": payload.kind, "environment_id": payload.environment_id})
            conn.commit()
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise HTTPException(status_code=409, detail="target name already exists") from exc
            raise
        row = conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
    return _target_dict(row)


@app.patch("/v1/targets/{target_id}")
def update_target(target_id: str, payload: TargetUpdate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="no fields supplied")
    with closing(db.connect()) as conn:
        if not conn.execute("SELECT 1 FROM targets WHERE id=?", (target_id,)).fetchone():
            raise HTTPException(status_code=404, detail="target not found")
        if "environment_id" in updates:
            _get_environment(conn, updates["environment_id"])
        if "credential_ref" in updates:
            _get_credential_ref(conn, updates["credential_ref"])
        if "integration_id" in updates and updates["integration_id"] and not conn.execute("SELECT 1 FROM integrations WHERE id=?", (updates["integration_id"],)).fetchone():
            raise HTTPException(status_code=404, detail="integration not found")
        if "scope" in updates:
            updates["scope_json"] = json.dumps(updates.pop("scope"), sort_keys=True)
        if "labels" in updates:
            updates["labels_json"] = json.dumps(updates.pop("labels"), sort_keys=True)
        updates["updated_at"] = int(time.time())
        fields = list(updates)
        conn.execute(f"UPDATE targets SET {', '.join(f'{f}=?' for f in fields)} WHERE id=?", (*[updates[f] for f in fields], target_id))
        db.audit(conn, "target.updated", "admin", "target", target_id, {"fields": fields})
        conn.commit()
        row = conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
    return _target_dict(row)


@app.delete("/v1/targets/{target_id}", status_code=204)
def delete_target(target_id: str, authorization: str | None = Header(default=None)) -> None:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        if conn.execute(
            "SELECT 1 FROM changesets WHERE target_id=? AND state NOT IN ('REJECTED','CANCELLED','EXPIRED','EXECUTED','FAILED','POLICY_DENIED','PREVIEW_FAILED') LIMIT 1",
            (target_id,),
        ).fetchone():
            raise HTTPException(status_code=409, detail="target has active ChangeSets")
        cur = conn.execute("DELETE FROM targets WHERE id=?", (target_id,))
        if not cur.rowcount:
            raise HTTPException(status_code=404, detail="target not found")
        db.audit(conn, "target.deleted", "admin", "target", target_id)
        conn.commit()


@app.get("/v1/changesets")
def list_changesets(limit: int = Query(default=200, ge=1, le=1000)) -> list[dict[str, Any]]:
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT * FROM changesets ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [_changeset_dict(row) for row in rows]


@app.get("/v1/changesets/{changeset_id}")
def get_changeset(changeset_id: str) -> dict[str, Any]:
    with closing(db.connect()) as conn:
        row = _changeset(conn, changeset_id)
    return _changeset_dict(row)


def _insert_changeset(
    conn,
    *,
    operation: str,
    adapter: str,
    target_id: str,
    requested_by: str,
    source_channel: str,
    source_revision: str | None,
    parameters: dict[str, Any],
    policy_generation: int,
    ttl_seconds: int,
) -> Any:
    created_at = int(time.time())
    expires_at = created_at + ttl_seconds
    changeset_id = f"chg_{uuid.uuid4().hex[:16]}"
    risk = classify(operation)
    target_snapshot = _target_snapshot(conn, target_id)
    if target_snapshot["status"] != "configured":
        raise HTTPException(status_code=409, detail="target is disabled")
    plan = {
        "schema_version": 2,
        "operation": operation,
        "adapter": adapter,
        "target_id": target_id,
        "source_revision": source_revision,
        "parameters": parameters,
        "policy_generation": policy_generation,
        "target_snapshot": target_snapshot,
    }
    plan_json = canonical_json(plan)
    plan_hash = sha256_hex(plan)
    conn.execute(
        """INSERT INTO changesets
        (id,operation,target_id,requested_by,source_channel,risk,parameters_json,content_hash,state,created_at,adapter,source_revision,plan_json,plan_hash,preview_json,approval_required,policy_generation,expires_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (changeset_id, operation, target_id, requested_by, source_channel, risk,
         json.dumps(parameters, sort_keys=True), plan_hash, "PLANNED", created_at, adapter, source_revision,
         plan_json, plan_hash, None, int(approval_required(risk)), policy_generation, expires_at, created_at),
    )
    db.audit(conn, "changeset.created", requested_by, "changeset", changeset_id, {"plan_hash": plan_hash, "risk": risk})
    return conn.execute("SELECT * FROM changesets WHERE id=?", (changeset_id,)).fetchone()


@app.post("/v1/changesets", status_code=201)
def create_changeset(payload: ChangeSetCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    if _is_infra_mutation(payload.adapter, payload.operation):
        _require_bot(authorization)
        _require_bot_origin(payload.source_channel)
    else:
        _require_admin(authorization)
    with closing(db.connect()) as conn:
        row = _insert_changeset(
            conn,
            operation=payload.operation,
            adapter=payload.adapter,
            target_id=payload.target_id,
            requested_by=payload.requested_by,
            source_channel=payload.source_channel,
            source_revision=payload.source_revision,
            parameters=payload.parameters,
            policy_generation=payload.policy_generation,
            ttl_seconds=payload.ttl_seconds,
        )
        conn.commit()
    return _changeset_dict(row)


@app.post("/v1/changesets/{changeset_id}/rollback-plan", status_code=201)
def create_rollback_plan(
    changeset_id: str,
    payload: RollbackPlanCreate,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_bot(authorization)
    _require_bot_origin(payload.source_channel)
    with closing(db.connect()) as conn:
        source = _changeset(conn, changeset_id)
        if source["state"] != "EXECUTED":
            raise HTTPException(status_code=409, detail="rollback can only be generated from an EXECUTED ChangeSet")
        execution = json.loads(source["execution_json"] or "null") or {}
        original = json.loads(source["plan_json"] or "{}")
        original_params = original.get("parameters") or {}
        operation = str(source["operation"] or "")

        if operation in {"kubernetes.manifest.apply", "kubernetes.manifest.delete", "kubernetes.manifest.rollback"}:
            before_state = execution.get("before_state")
            if not isinstance(before_state, dict) or not before_state.get("resources"):
                raise HTTPException(status_code=409, detail="executed ChangeSet has no captured Kubernetes before-state")
            actions = []
            for item in before_state.get("resources") or []:
                ref = item.get("resource") or {}
                if item.get("exists"):
                    manifest = item.get("manifest")
                    if not manifest:
                        raise HTTPException(status_code=409, detail="captured rollback state is incomplete")
                    actions.append({"action": "apply", "resource": ref, "manifest": manifest})
                else:
                    actions.append({"action": "delete", "resource": ref})
            rb_operation = "kubernetes.manifest.rollback"
            rb_adapter = "kubernetes"
            rb_params = {
                "namespace": original_params.get("namespace", "default"),
                "source_changeset_id": changeset_id,
                "actions": actions,
            }
        elif operation in {"helm.install", "helm.upgrade", "helm.rollback"}:
            before = execution.get("before_release") or {}
            release = original_params.get("release")
            namespace = original_params.get("namespace", "default")
            if before.get("exists") and int(before.get("revision") or 0) >= 1:
                rb_operation = "helm.rollback"
                rb_adapter = "helm"
                rb_params = {
                    "release": release,
                    "namespace": namespace,
                    "revision": int(before["revision"]),
                    "source_changeset_id": changeset_id,
                }
            elif not before.get("exists"):
                rb_operation = "helm.uninstall"
                rb_adapter = "helm"
                rb_params = {
                    "release": release,
                    "namespace": namespace,
                    "source_changeset_id": changeset_id,
                }
            else:
                raise HTTPException(status_code=409, detail="executed Helm ChangeSet has no usable previous release revision")
        else:
            raise HTTPException(status_code=422, detail=f"rollback is not implemented for {operation}")

        row = _insert_changeset(
            conn,
            operation=rb_operation,
            adapter=rb_adapter,
            target_id=source["target_id"],
            requested_by=payload.requested_by,
            source_channel=payload.source_channel,
            source_revision=None,
            parameters=rb_params,
            policy_generation=int(source["policy_generation"] or 1),
            ttl_seconds=payload.ttl_seconds,
        )
        db.audit(conn, "changeset.rollback_planned", payload.requested_by, "changeset", row["id"], {
            "source_changeset_id": changeset_id,
            "plan_hash": row["plan_hash"],
        })
        conn.commit()
    return _changeset_dict(row)


@app.post("/v1/changesets/{changeset_id}/preview")
def preview_changeset(changeset_id: str, payload: PreviewCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    now = int(time.time())
    with closing(db.connect()) as conn:
        row = _changeset(conn, changeset_id)
        _require_infra_actor(row, authorization)
        if row["state"] not in {"PLANNED", "PREVIEWED"}:
            raise HTTPException(status_code=409, detail=f"cannot preview ChangeSet in state {row['state']}")
        preview = {"summary": payload.summary, "details": payload.details, "generated_at": now, "source": "planner"}
        conn.execute("UPDATE changesets SET preview_json=?,state='PREVIEWED',updated_at=? WHERE id=?", (json.dumps(preview, sort_keys=True), now, changeset_id))
        db.audit(conn, "changeset.previewed", "planner", "changeset", changeset_id, {"plan_hash": row["plan_hash"]})
        conn.commit()
        updated = conn.execute("SELECT * FROM changesets WHERE id=?", (changeset_id,)).fetchone()
    return _changeset_dict(updated)


@app.post("/v1/changesets/{changeset_id}/request-approval")
def request_approval(changeset_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    now = int(time.time())
    with closing(db.connect()) as conn:
        row = _changeset(conn, changeset_id)
        _require_infra_actor(row, authorization)
        if not row["approval_required"]:
            raise HTTPException(status_code=409, detail="risk engine does not require approval for this ChangeSet")
        if row["state"] != "PREVIEWED":
            raise HTTPException(status_code=409, detail="ChangeSet must be PREVIEWED before approval is requested")
        conn.execute("UPDATE changesets SET state='AWAITING_APPROVAL',updated_at=? WHERE id=?", (now, changeset_id))
        db.audit(conn, "changeset.approval_requested", row["requested_by"], "changeset", changeset_id, {"plan_hash": row["plan_hash"], "risk": row["risk"]})
        conn.commit()
        updated = conn.execute("SELECT * FROM changesets WHERE id=?", (changeset_id,)).fetchone()
    return _changeset_dict(updated)


@app.post("/v1/changesets/{changeset_id}/approve", status_code=201)
def approve_changeset(changeset_id: str, payload: ApprovalDecision, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    now = int(time.time())
    with closing(db.connect()) as conn:
        row = _changeset(conn, changeset_id)
        if _is_infra_mutation(row["adapter"], row["operation"]):
            _require_approval_bot(authorization)
        else:
            _require_admin(authorization)
        if row["state"] != "AWAITING_APPROVAL":
            raise HTTPException(status_code=409, detail="ChangeSet is not awaiting approval")
        if payload.plan_hash != row["plan_hash"]:
            raise HTTPException(status_code=409, detail="approval hash does not match current ChangeSet plan")
        if row["risk"] in {"HIGH", "CRITICAL"} and payload.approver == row["requested_by"]:
            raise HTTPException(status_code=403, detail="requester cannot self-approve HIGH/CRITICAL ChangeSets")
        approval_id = f"apr_{uuid.uuid4().hex[:16]}"
        expires_at = min(now + payload.ttl_seconds, int(row["expires_at"] or now + payload.ttl_seconds))
        conn.execute(
            "INSERT INTO approvals (id,changeset_id,plan_hash,approver,status,issued_at,expires_at,decided_at) VALUES (?,?,?,?,?,?,?,?)",
            (approval_id, changeset_id, row["plan_hash"], payload.approver, "APPROVED", now, expires_at, now),
        )
        conn.execute("UPDATE changesets SET state='APPROVED',updated_at=? WHERE id=?", (now, changeset_id))
        db.audit(conn, "changeset.approved", payload.approver, "changeset", changeset_id, {"approval_id": approval_id, "plan_hash": row["plan_hash"], "expires_at": expires_at})
        conn.commit()
    return {"id": approval_id, "changeset_id": changeset_id, "plan_hash": payload.plan_hash, "approver": payload.approver, "status": "APPROVED", "issued_at": now, "expires_at": expires_at, "execution_enabled": os.getenv("HERMES_EXECUTION_ENABLED", "false").lower() == "true"}


@app.post("/v1/changesets/{changeset_id}/reject")
def reject_changeset(changeset_id: str, payload: RejectDecision, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    now = int(time.time())
    with closing(db.connect()) as conn:
        row = _changeset(conn, changeset_id)
        if _is_infra_mutation(row["adapter"], row["operation"]):
            _require_approval_bot(authorization)
        else:
            _require_admin(authorization)
        if row["state"] in TERMINAL_CHANGESET_STATES:
            raise HTTPException(status_code=409, detail=f"ChangeSet already terminal: {row['state']}")
        conn.execute("UPDATE changesets SET state='REJECTED',updated_at=? WHERE id=?", (now, changeset_id))
        conn.execute("UPDATE approvals SET status='REJECTED',decided_at=?,reason=? WHERE changeset_id=? AND status='APPROVED'", (now, payload.reason, changeset_id))
        db.audit(conn, "changeset.rejected", payload.actor, "changeset", changeset_id, {"reason": payload.reason, "plan_hash": row["plan_hash"]})
        conn.commit()
        updated = conn.execute("SELECT * FROM changesets WHERE id=?", (changeset_id,)).fetchone()
    return _changeset_dict(updated)


@app.post("/v1/changesets/{changeset_id}/cancel")
def cancel_changeset(changeset_id: str, payload: RejectDecision, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    now = int(time.time())
    with closing(db.connect()) as conn:
        row = _changeset(conn, changeset_id)
        if row["state"] in TERMINAL_CHANGESET_STATES:
            raise HTTPException(status_code=409, detail=f"ChangeSet already terminal: {row['state']}")
        conn.execute("UPDATE changesets SET state='CANCELLED',updated_at=? WHERE id=?", (now, changeset_id))
        conn.execute("UPDATE approvals SET status='CANCELLED',decided_at=?,reason=? WHERE changeset_id=? AND status='APPROVED'", (now, payload.reason, changeset_id))
        db.audit(conn, "changeset.cancelled", payload.actor, "changeset", changeset_id, {"reason": payload.reason, "plan_hash": row["plan_hash"]})
        conn.commit()
        updated = conn.execute("SELECT * FROM changesets WHERE id=?", (changeset_id,)).fetchone()
    return _changeset_dict(updated)


@app.post("/v1/kubernetes/targets/{target_id}/discover")
async def discover_kubernetes_target(target_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    with closing(db.connect()) as conn:
        snapshot = _target_snapshot(conn, target_id)
    if snapshot["kind"] != "kubernetes":
        raise HTTPException(status_code=422, detail="target is not kubernetes")
    result = await kubernetes_broker.post("/v1/discover", {"target_snapshot": snapshot})
    with closing(db.connect()) as conn:
        db.audit(conn, "kubernetes.discovered", "admin", "target", target_id, {"snapshot_hash": snapshot["snapshot_hash"]})
        conn.commit()
    return result


@app.post("/v1/changesets/{changeset_id}/preview-live")
async def preview_changeset_live(changeset_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    with closing(db.connect()) as conn:
        row = _changeset(conn, changeset_id)
        _require_infra_actor(row, authorization)
        if row["state"] not in {"PLANNED", "PREVIEWED"}:
            raise HTTPException(status_code=409, detail=f"cannot preview ChangeSet in state {row['state']}")
        if row["adapter"] not in {"kubernetes", "helm"}:
            raise HTTPException(status_code=422, detail="live preview is currently available only for Kubernetes/Helm adapters")
        plan = json.loads(row["plan_json"] or "{}")
        if sha256_hex(plan) != row["plan_hash"]:
            raise HTTPException(status_code=409, detail="stored ChangeSet hash verification failed")
        current = _target_snapshot(conn, row["target_id"])
        if current != plan.get("target_snapshot"):
            raise HTTPException(status_code=409, detail="target or credential metadata changed after planning; create a new ChangeSet")
    try:
        result = await kubernetes_broker.post("/v1/preview", {"plan": plan})
    except HTTPException as exc:
        now = int(time.time())
        state = "POLICY_DENIED" if exc.status_code == 403 else "PREVIEW_FAILED"
        failure = {
            "summary": "Live broker preview denied" if state == "POLICY_DENIED" else "Live broker preview failed",
            "details": {"status_code": exc.status_code, "detail": exc.detail},
            "generated_at": now,
            "source": "kubernetes-broker",
        }
        with closing(db.connect()) as conn:
            conn.execute(
                "UPDATE changesets SET preview_json=?,state=?,updated_at=? WHERE id=?",
                (json.dumps(failure, sort_keys=True), state, now, changeset_id),
            )
            db.audit(
                conn,
                "changeset.policy_denied" if state == "POLICY_DENIED" else "changeset.preview_failed",
                "kubernetes-broker",
                "changeset",
                changeset_id,
                {"plan_hash": row["plan_hash"], "status_code": exc.status_code, "detail": exc.detail},
            )
            conn.commit()
        raise
    now = int(time.time())
    preview = {"summary": result.get("summary", "Live broker preview completed"), "details": result, "generated_at": now, "source": "kubernetes-broker"}
    with closing(db.connect()) as conn:
        conn.execute("UPDATE changesets SET preview_json=?,state='PREVIEWED',updated_at=? WHERE id=?", (json.dumps(preview, sort_keys=True), now, changeset_id))
        db.audit(conn, "changeset.previewed.live", "kubernetes-broker", "changeset", changeset_id, {"plan_hash": row["plan_hash"]})
        conn.commit()
        updated = conn.execute("SELECT * FROM changesets WHERE id=?", (changeset_id,)).fetchone()
    return _changeset_dict(updated)


@app.post("/v1/changesets/{changeset_id}/execute")
async def execute_changeset(changeset_id: str, payload: ExecuteDecision, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    if os.getenv("HERMES_EXECUTION_ENABLED", "false").lower() != "true":
        raise HTTPException(status_code=403, detail="Control Plane execution is disabled; set HERMES_EXECUTION_ENABLED=true only after review")
    now = int(time.time())
    with closing(db.connect()) as conn:
        row = _changeset(conn, changeset_id)
        _require_infra_actor(row, authorization)
        if row["state"] not in {"PREVIEWED", "APPROVED"}:
            raise HTTPException(status_code=409, detail="ChangeSet must have a live preview and any required approval before execution")
        plan = json.loads(row["plan_json"] or "{}")
        if sha256_hex(plan) != row["plan_hash"]:
            raise HTTPException(status_code=409, detail="stored ChangeSet hash verification failed")
        current = _target_snapshot(conn, row["target_id"])
        if current != plan.get("target_snapshot"):
            raise HTTPException(status_code=409, detail="target or credential metadata changed after approval; create a new ChangeSet")
        preview = json.loads(row["preview_json"] or "null")
        if not preview or preview.get("source") != "kubernetes-broker":
            raise HTTPException(status_code=409, detail="a live Kubernetes Broker preview is required")
        if row["approval_required"]:
            approval = conn.execute("SELECT * FROM approvals WHERE changeset_id=? AND plan_hash=? AND status='APPROVED' ORDER BY issued_at DESC LIMIT 1", (changeset_id, row["plan_hash"])).fetchone()
            if not approval or int(approval["expires_at"]) < now:
                raise HTTPException(status_code=409, detail="no valid approval is bound to this exact plan hash")
        preview_details = (preview.get("details") or {}) if isinstance(preview, dict) else {}
        preconditions = {}
        if preview_details.get("live_state_hash"):
            preconditions["live_state_hash"] = preview_details["live_state_hash"]
        if preview_details.get("release_snapshot_hash"):
            preconditions["release_snapshot_hash"] = preview_details["release_snapshot_hash"]
        try:
            ticket, signature = issue_ticket(
                changeset_id,
                row["plan_hash"],
                plan,
                preconditions=preconditions,
            )
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        conn.execute("UPDATE changesets SET state='EXECUTING',updated_at=? WHERE id=?", (now, changeset_id))
        db.audit(conn, "changeset.execution.started", payload.actor, "changeset", changeset_id, {"plan_hash": row["plan_hash"]})
        conn.commit()
    try:
        result = await kubernetes_broker.post("/v1/execute", {"ticket": ticket, "signature": signature})
        state = "EXECUTED"
    except HTTPException as exc:
        result = {"error": exc.detail, "status_code": exc.status_code}
        state = "FAILED"
    finished = int(time.time())
    with closing(db.connect()) as conn:
        conn.execute("UPDATE changesets SET state=?,execution_json=?,executed_at=?,updated_at=? WHERE id=?", (state, json.dumps(result, sort_keys=True), finished, finished, changeset_id))
        db.audit(conn, f"changeset.execution.{state.lower()}", payload.actor, "changeset", changeset_id, {"plan_hash": ticket["plan_hash"]})
        conn.commit()
        updated = conn.execute("SELECT * FROM changesets WHERE id=?", (changeset_id,)).fetchone()
    if state == "FAILED":
        raise HTTPException(status_code=502, detail=_changeset_dict(updated))
    return _changeset_dict(updated)


@app.get("/v1/kubernetes/broker-health")
async def kubernetes_broker_health() -> dict[str, Any]:
    return await kubernetes_broker.health()


@app.get("/v1/changesets/{changeset_id}/approvals")
def list_approvals(changeset_id: str) -> list[dict[str, Any]]:
    with closing(db.connect()) as conn:
        if not conn.execute("SELECT 1 FROM changesets WHERE id=?", (changeset_id,)).fetchone():
            raise HTTPException(status_code=404, detail="changeset not found")
        rows = conn.execute("SELECT * FROM approvals WHERE changeset_id=? ORDER BY issued_at DESC", (changeset_id,)).fetchall()
    return [dict(row) for row in rows]


@app.get("/v1/audit")
def list_audit(limit: int = Query(default=200, ge=1, le=2000), subject_id: str | None = None) -> list[dict[str, Any]]:
    with closing(db.connect()) as conn:
        if subject_id:
            rows = conn.execute("SELECT * FROM audit_events WHERE subject_id=? ORDER BY id DESC LIMIT ?", (subject_id, limit)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        item["payload"] = json.loads(item.pop("payload_json") or "{}")
        out.append(item)
    return out
