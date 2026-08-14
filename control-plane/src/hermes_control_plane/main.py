from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
import uuid
from contextlib import closing
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

VERSION = "0.5.10-alpha.1"
DB_PATH = Path(os.getenv("HERMES_CONTROL_DB", "/data/control-plane.sqlite3"))
ADMIN_TOKEN = os.getenv("HERMES_CONTROL_ADMIN_TOKEN", "")

app = FastAPI(
    title="Hermes Control Plane API",
    version=VERSION,
    description="v0.5.10 alpha management API foundation",
)


def _db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    with closing(_db()) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS integrations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL,
                environment TEXT NOT NULL,
                endpoint TEXT,
                credential_ref TEXT,
                connection_mode TEXT NOT NULL,
                labels_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS changesets (
                id TEXT PRIMARY KEY,
                operation TEXT NOT NULL,
                target_id TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                source_channel TEXT NOT NULL,
                risk TEXT NOT NULL,
                parameters_json TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )
        conn.commit()


@app.on_event("startup")
def startup() -> None:
    _init_db()


def _require_admin(authorization: str | None) -> None:
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=503, detail="HERMES_CONTROL_ADMIN_TOKEN is not configured")
    if authorization != f"Bearer {ADMIN_TOKEN}":
        raise HTTPException(status_code=401, detail="invalid admin token")


class IntegrationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    kind: Literal["kubernetes", "docker", "swarm", "ssh", "github", "gitlab", "registry", "helm"]
    environment: str = Field(default="default", min_length=1, max_length=80)
    endpoint: str | None = None
    credential_ref: str | None = None
    connection_mode: Literal["direct", "agent"] = "direct"
    labels: dict[str, str] = Field(default_factory=dict)


class IntegrationUpdate(BaseModel):
    environment: str | None = Field(default=None, min_length=1, max_length=80)
    endpoint: str | None = None
    credential_ref: str | None = None
    connection_mode: Literal["direct", "agent"] | None = None
    labels: dict[str, str] | None = None
    status: Literal["configured", "disabled"] | None = None


class ChangeSetCreate(BaseModel):
    operation: str = Field(min_length=1, max_length=160)
    target_id: str = Field(min_length=1, max_length=160)
    requested_by: str = Field(min_length=1, max_length=160)
    source_channel: Literal["ui", "telegram", "api", "cli"] = "api"
    risk: Literal["READ", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    parameters: dict[str, Any] = Field(default_factory=dict)


@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True, "service": "hermes-control-plane", "version": VERSION}


@app.get("/v1/system")
def system() -> dict[str, Any]:
    return {
        "name": "Hermes Control Plane",
        "version": VERSION,
        "stage": "alpha",
        "runtime": os.getenv("HERMES_RUNTIME", "docker"),
        "warning": "DevOps mutation authorization is not production-complete in alpha.1",
    }


@app.get("/v1/integrations")
def list_integrations() -> list[dict[str, Any]]:
    with closing(_db()) as conn:
        rows = conn.execute("SELECT * FROM integrations ORDER BY name").fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["labels"] = json.loads(item.pop("labels_json"))
        # Credential IDs are references only. Raw secrets are never stored by this API.
        result.append(item)
    return result


@app.post("/v1/integrations", status_code=201)
def create_integration(payload: IntegrationCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    now = int(time.time())
    integration_id = f"int_{uuid.uuid4().hex[:16]}"
    with closing(_db()) as conn:
        try:
            conn.execute(
                """INSERT INTO integrations
                (id,name,kind,environment,endpoint,credential_ref,connection_mode,labels_json,status,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    integration_id,
                    payload.name,
                    payload.kind,
                    payload.environment,
                    payload.endpoint,
                    payload.credential_ref,
                    payload.connection_mode,
                    json.dumps(payload.labels, sort_keys=True),
                    "configured",
                    now,
                    now,
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="integration name already exists") from exc
    return {"id": integration_id, **payload.model_dump(), "status": "configured"}


@app.patch("/v1/integrations/{integration_id}")
def update_integration(
    integration_id: str,
    payload: IntegrationUpdate,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin(authorization)
    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="no fields supplied")
    with closing(_db()) as conn:
        row = conn.execute("SELECT * FROM integrations WHERE id = ?", (integration_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="integration not found")
        current = dict(row)
        if "labels" in updates:
            updates["labels_json"] = json.dumps(updates.pop("labels"), sort_keys=True)
        updates["updated_at"] = int(time.time())
        allowed = {"environment", "endpoint", "credential_ref", "connection_mode", "labels_json", "status", "updated_at"}
        fields = [k for k in updates if k in allowed]
        values = [updates[k] for k in fields]
        conn.execute(
            f"UPDATE integrations SET {', '.join(f'{k} = ?' for k in fields)} WHERE id = ?",
            (*values, integration_id),
        )
        conn.commit()
        updated = conn.execute("SELECT * FROM integrations WHERE id = ?", (integration_id,)).fetchone()
    item = dict(updated)
    item["labels"] = json.loads(item.pop("labels_json"))
    return item


@app.delete("/v1/integrations/{integration_id}", status_code=204)
def delete_integration(integration_id: str, authorization: str | None = Header(default=None)) -> None:
    _require_admin(authorization)
    with closing(_db()) as conn:
        cur = conn.execute("DELETE FROM integrations WHERE id = ?", (integration_id,))
        conn.commit()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="integration not found")


@app.get("/v1/changesets")
def list_changesets() -> list[dict[str, Any]]:
    with closing(_db()) as conn:
        rows = conn.execute("SELECT * FROM changesets ORDER BY created_at DESC LIMIT 200").fetchall()
    out = []
    for row in rows:
        item = dict(row)
        item["parameters"] = json.loads(item.pop("parameters_json"))
        out.append(item)
    return out


@app.post("/v1/changesets", status_code=201)
def create_changeset(payload: ChangeSetCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    canonical = json.dumps(payload.model_dump(), sort_keys=True, separators=(",", ":"))
    content_hash = hashlib.sha256(canonical.encode()).hexdigest()
    changeset_id = f"chg_{uuid.uuid4().hex[:16]}"
    created_at = int(time.time())
    with closing(_db()) as conn:
        conn.execute(
            """INSERT INTO changesets
            (id,operation,target_id,requested_by,source_channel,risk,parameters_json,content_hash,state,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                changeset_id,
                payload.operation,
                payload.target_id,
                payload.requested_by,
                payload.source_channel,
                payload.risk,
                json.dumps(payload.parameters, sort_keys=True),
                content_hash,
                "PLANNED",
                created_at,
            ),
        )
        conn.commit()
    return {
        "id": changeset_id,
        **payload.model_dump(),
        "content_hash": content_hash,
        "state": "PLANNED",
        "created_at": created_at,
        "executable": False,
        "note": "alpha.1 creates immutable plan records only; execution binding is planned for alpha.3",
    }
