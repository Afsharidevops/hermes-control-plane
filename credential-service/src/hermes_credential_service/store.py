from __future__ import annotations

import os
import sqlite3
import time
from contextlib import closing
from pathlib import Path

DB_PATH = Path(os.getenv("HERMES_CREDENTIAL_DB", "/data/credential-service.sqlite3"))


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with closing(connect()) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS credentials (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL,
                backend TEXT NOT NULL,
                external_ref TEXT,
                ciphertext BLOB,
                fingerprint TEXT,
                metadata_json TEXT NOT NULL,
                status TEXT NOT NULL,
                version INTEGER NOT NULL,
                key_version TEXT,
                sync_status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                last_test_at INTEGER,
                last_test_status TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                credential_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )
        conn.commit()


def audit(conn: sqlite3.Connection, event_type: str, actor: str, credential_id: str, payload_json: str = "{}") -> None:
    conn.execute(
        "INSERT INTO audit_events (event_type,actor,credential_id,payload_json,created_at) VALUES (?,?,?,?,?)",
        (event_type, actor, credential_id, payload_json, int(time.time())),
    )
