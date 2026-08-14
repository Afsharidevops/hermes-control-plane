from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any

DB_PATH = Path(os.getenv("HERMES_CONTROL_DB", "/data/control-plane.sqlite3"))


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    except sqlite3.OperationalError:
        return set()
    return {str(row[1]) for row in rows}


def slugify(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return value or "environment"


def stable_env_id(slug: str) -> str:
    return "env_" + hashlib.sha256(slug.encode("utf-8")).hexdigest()[:12]


def _ensure_environment(conn: sqlite3.Connection, name: str) -> str:
    slug = slugify(name)
    row = conn.execute("SELECT id FROM environments WHERE slug = ?", (slug,)).fetchone()
    if row:
        return str(row["id"])
    now = int(time.time())
    env_id = stable_env_id(slug)
    conn.execute(
        "INSERT OR IGNORE INTO environments (id,name,slug,risk_level,labels_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
        (env_id, name, slug, "LOW", "{}", now, now),
    )
    return env_id


def init_db() -> None:
    with closing(connect()) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS environments (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                slug TEXT NOT NULL UNIQUE,
                risk_level TEXT NOT NULL,
                labels_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS credential_refs (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL,
                provider TEXT,
                status TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL,
                environment_id TEXT NOT NULL,
                integration_id TEXT,
                credential_ref TEXT,
                connection_mode TEXT NOT NULL,
                address TEXT,
                scope_json TEXT NOT NULL,
                labels_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(environment_id) REFERENCES environments(id)
            );

            CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY,
                changeset_id TEXT NOT NULL,
                plan_hash TEXT NOT NULL,
                approver TEXT NOT NULL,
                status TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                decided_at INTEGER,
                reason TEXT,
                FOREIGN KEY(changeset_id) REFERENCES changesets(id)
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                subject_type TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )

        # Alpha.1 compatibility: preserve the old integrations table and extend it in place.
        if not _columns(conn, "integrations"):
            conn.execute(
                """CREATE TABLE integrations (
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
                    updated_at INTEGER NOT NULL,
                    environment_id TEXT,
                    allowed_scope_json TEXT NOT NULL DEFAULT '{}',
                    health_status TEXT NOT NULL DEFAULT 'UNKNOWN',
                    last_health_at INTEGER,
                    last_health_detail TEXT
                )"""
            )
        else:
            cols = _columns(conn, "integrations")
            additions = {
                "environment_id": "TEXT",
                "allowed_scope_json": "TEXT NOT NULL DEFAULT '{}'",
                "health_status": "TEXT NOT NULL DEFAULT 'UNKNOWN'",
                "last_health_at": "INTEGER",
                "last_health_detail": "TEXT",
            }
            for name, ddl in additions.items():
                if name not in cols:
                    conn.execute(f"ALTER TABLE integrations ADD COLUMN {name} {ddl}")

        if not _columns(conn, "changesets"):
            conn.execute(
                """CREATE TABLE changesets (
                    id TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    requested_by TEXT NOT NULL,
                    source_channel TEXT NOT NULL,
                    risk TEXT NOT NULL,
                    parameters_json TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    adapter TEXT NOT NULL DEFAULT 'generic',
                    source_revision TEXT,
                    plan_json TEXT,
                    plan_hash TEXT,
                    preview_json TEXT,
                    approval_required INTEGER NOT NULL DEFAULT 0,
                    policy_generation INTEGER NOT NULL DEFAULT 1,
                    expires_at INTEGER,
                    updated_at INTEGER
                )"""
            )
        else:
            cols = _columns(conn, "changesets")
            additions = {
                "adapter": "TEXT NOT NULL DEFAULT 'generic'",
                "source_revision": "TEXT",
                "plan_json": "TEXT",
                "plan_hash": "TEXT",
                "preview_json": "TEXT",
                "approval_required": "INTEGER NOT NULL DEFAULT 0",
                "policy_generation": "INTEGER NOT NULL DEFAULT 1",
                "expires_at": "INTEGER",
                "updated_at": "INTEGER",
            }
            for name, ddl in additions.items():
                if name not in cols:
                    conn.execute(f"ALTER TABLE changesets ADD COLUMN {name} {ddl}")

        default_env = _ensure_environment(conn, "default")
        rows = conn.execute("SELECT id, environment, environment_id FROM integrations").fetchall()
        for row in rows:
            if not row["environment_id"]:
                env_name = row["environment"] or "default"
                env_id = _ensure_environment(conn, env_name)
                conn.execute("UPDATE integrations SET environment_id = ? WHERE id = ?", (env_id, row["id"]))
        # Keep a valid environment even if a manually-created alpha.1 row was incomplete.
        conn.execute("UPDATE integrations SET environment_id = ? WHERE environment_id IS NULL", (default_env,))

        # Backfill alpha.1 ChangeSets so old plan records remain readable.
        rows = conn.execute("SELECT * FROM changesets WHERE plan_hash IS NULL OR plan_json IS NULL").fetchall()
        for row in rows:
            params = json.loads(row["parameters_json"] or "{}")
            plan = {
                "schema_version": 1,
                "operation": row["operation"],
                "adapter": row["adapter"] or "generic",
                "target_id": row["target_id"],
                "source_revision": row["source_revision"],
                "parameters": params,
                "policy_generation": row["policy_generation"] or 1,
            }
            canonical = json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            plan_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            conn.execute(
                "UPDATE changesets SET plan_json=?, plan_hash=?, content_hash=?, updated_at=COALESCE(updated_at,created_at) WHERE id=?",
                (canonical, plan_hash, plan_hash, row["id"]),
            )

        conn.execute("PRAGMA user_version = 2")
        conn.commit()


def audit(conn: sqlite3.Connection, event_type: str, actor: str, subject_type: str, subject_id: str, payload: dict[str, Any] | None = None) -> None:
    conn.execute(
        "INSERT INTO audit_events (event_type,actor,subject_type,subject_id,payload_json,created_at) VALUES (?,?,?,?,?,?)",
        (event_type, actor, subject_type, subject_id, json.dumps(payload or {}, sort_keys=True), int(time.time())),
    )
