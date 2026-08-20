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

            CREATE TABLE IF NOT EXISTS servers (
                id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL UNIQUE,
                environment_id TEXT NOT NULL,
                management_ip TEXT NOT NULL,
                provisioning_ip TEXT,
                bmc_ip TEXT,
                ssh_port INTEGER NOT NULL,
                ssh_user TEXT NOT NULL,
                host_fingerprint TEXT NOT NULL,
                connection_mode TEXT NOT NULL,
                credential_ref TEXT NOT NULL,
                bmc_credential_ref TEXT,
                architecture TEXT,
                site TEXT,
                rack TEXT,
                zone TEXT,
                labels_json TEXT NOT NULL,
                inventory_json TEXT NOT NULL DEFAULT '{}',
                discovery_status TEXT NOT NULL DEFAULT 'UNKNOWN',
                preflight_status TEXT NOT NULL DEFAULT 'UNKNOWN',
                preflight_json TEXT,
                last_preflight_at INTEGER,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(environment_id) REFERENCES environments(id),
                FOREIGN KEY(credential_ref) REFERENCES credential_refs(id),
                FOREIGN KEY(bmc_credential_ref) REFERENCES credential_refs(id)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_servers_management_ip ON servers(management_ip);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_servers_provisioning_ip ON servers(provisioning_ip) WHERE provisioning_ip IS NOT NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS idx_servers_bmc_ip ON servers(bmc_ip) WHERE bmc_ip IS NOT NULL;

            CREATE TABLE IF NOT EXISTS provider_jobs (
                id TEXT PRIMARY KEY,
                provider_id TEXT NOT NULL,
                server_id TEXT NOT NULL,
                changeset_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                state TEXT NOT NULL,
                stage TEXT NOT NULL,
                attempt INTEGER NOT NULL DEFAULT 1,
                max_attempts INTEGER NOT NULL DEFAULT 3,
                plan_hash TEXT NOT NULL,
                request_json TEXT NOT NULL,
                result_json TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(server_id) REFERENCES servers(id),
                FOREIGN KEY(changeset_id) REFERENCES changesets(id)
            );

            CREATE TABLE IF NOT EXISTS provider_job_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                stage TEXT NOT NULL,
                status TEXT NOT NULL,
                message TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(job_id) REFERENCES provider_jobs(id)
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
                policy_generation INTEGER NOT NULL DEFAULT 1,
                policy_id TEXT NOT NULL DEFAULT 'risk-baseline',
                policy_version INTEGER NOT NULL DEFAULT 1,
                nonce TEXT,
                mac TEXT,
                consumed_at INTEGER,
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

            CREATE TABLE IF NOT EXISTS system_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, status TEXT NOT NULL,
                expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, used_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL UNIQUE, status TEXT NOT NULL,
                capabilities_json TEXT NOT NULL, enrolled_at INTEGER NOT NULL, last_seen_at INTEGER, revoked_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS agent_nonces (
                agent_id TEXT NOT NULL, nonce TEXT NOT NULL, seen_at INTEGER NOT NULL,
                PRIMARY KEY(agent_id,nonce), FOREIGN KEY(agent_id) REFERENCES agents(id)
            );

            CREATE TABLE IF NOT EXISTS applications (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                environment_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                source_repository TEXT NOT NULL,
                revision_policy TEXT NOT NULL,
                build_context TEXT NOT NULL,
                image_repository TEXT,
                deployment_type TEXT NOT NULL,
                values_files_json TEXT NOT NULL,
                verification_checks_json TEXT NOT NULL,
                rollback_strategy_json TEXT NOT NULL,
                labels_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(environment_id) REFERENCES environments(id),
                FOREIGN KEY(target_id) REFERENCES targets(id)
            );

            CREATE TABLE IF NOT EXISTS agent_tasks (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                changeset_id TEXT NOT NULL,
                capability TEXT NOT NULL,
                policy_generation INTEGER NOT NULL,
                envelope_json TEXT NOT NULL,
                signature TEXT NOT NULL,
                state TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                claim_nonce_hash TEXT,
                claimed_at INTEGER,
                completed_at INTEGER,
                result_json TEXT,
                FOREIGN KEY(agent_id) REFERENCES agents(id),
                FOREIGN KEY(changeset_id) REFERENCES changesets(id)
            );
            """
        )

        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cluster_blueprints (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                provider TEXT NOT NULL,
                provider_version TEXT NOT NULL,
                kubernetes_version TEXT NOT NULL,
                network_plugin TEXT NOT NULL,
                hubble_enabled INTEGER NOT NULL,
                radar_enabled INTEGER NOT NULL,
                topology_json TEXT NOT NULL,
                addon_defaults_json TEXT NOT NULL,
                addon_versions_json TEXT NOT NULL,
                labels_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cluster_profiles (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                environment_id TEXT NOT NULL,
                blueprint_id TEXT NOT NULL,
                server_ids_json TEXT NOT NULL,
                overrides_json TEXT NOT NULL,
                labels_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(environment_id) REFERENCES environments(id),
                FOREIGN KEY(blueprint_id) REFERENCES cluster_blueprints(id)
            );

            CREATE TABLE IF NOT EXISTS clusters (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                environment_id TEXT NOT NULL,
                profile_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                kubernetes_version TEXT NOT NULL,
                network_plugin TEXT NOT NULL,
                state TEXT NOT NULL,
                labels_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(environment_id) REFERENCES environments(id),
                FOREIGN KEY(profile_id) REFERENCES cluster_profiles(id)
            );

            CREATE TABLE IF NOT EXISTS node_roles (
                id TEXT PRIMARY KEY,
                profile_id TEXT NOT NULL,
                role TEXT NOT NULL,
                server_ids_json TEXT NOT NULL,
                configuration_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(profile_id) REFERENCES cluster_profiles(id)
            );

            CREATE TABLE IF NOT EXISTS provisioning_runs (
                id TEXT PRIMARY KEY,
                cluster_id TEXT NOT NULL,
                profile_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                state TEXT NOT NULL,
                stage TEXT NOT NULL,
                changeset_id TEXT NOT NULL,
                provider_job_ids_json TEXT NOT NULL,
                plan_json TEXT NOT NULL,
                result_json TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(cluster_id) REFERENCES clusters(id),
                FOREIGN KEY(profile_id) REFERENCES cluster_profiles(id),
                FOREIGN KEY(changeset_id) REFERENCES changesets(id)
            );

            CREATE TABLE IF NOT EXISTS addon_plans (
                id TEXT PRIMARY KEY,
                cluster_id TEXT NOT NULL,
                state TEXT NOT NULL,
                changeset_id TEXT NOT NULL,
                plan_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(cluster_id) REFERENCES clusters(id),
                FOREIGN KEY(changeset_id) REFERENCES changesets(id)
            );

            CREATE TABLE IF NOT EXISTS upgrade_plans (
                id TEXT PRIMARY KEY,
                cluster_id TEXT NOT NULL,
                state TEXT NOT NULL,
                changeset_id TEXT NOT NULL,
                plan_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(cluster_id) REFERENCES clusters(id),
                FOREIGN KEY(changeset_id) REFERENCES changesets(id)
            );

            CREATE TABLE IF NOT EXISTS backup_plans (
                id TEXT PRIMARY KEY,
                cluster_id TEXT NOT NULL,
                state TEXT NOT NULL,
                changeset_id TEXT NOT NULL,
                plan_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(cluster_id) REFERENCES clusters(id),
                FOREIGN KEY(changeset_id) REFERENCES changesets(id)
            );

            CREATE TABLE IF NOT EXISTS kubernetes_intelligence_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cluster_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                observed_at INTEGER NOT NULL,
                summary_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(cluster_id) REFERENCES clusters(id)
            );

            CREATE TABLE IF NOT EXISTS hubble_flow_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cluster_id TEXT NOT NULL,
                observed_at INTEGER NOT NULL,
                fingerprint TEXT NOT NULL,
                event_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                UNIQUE(cluster_id, fingerprint),
                FOREIGN KEY(cluster_id) REFERENCES clusters(id)
            );
            CREATE INDEX IF NOT EXISTS idx_hubble_flow_events_cluster_time
                ON hubble_flow_events(cluster_id, observed_at DESC, id DESC);
            """
        )

        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS infrastructure_providers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                credential_ref TEXT NOT NULL,
                api_version TEXT NOT NULL,
                implementation_version TEXT NOT NULL,
                site TEXT,
                zone TEXT,
                capabilities_json TEXT NOT NULL,
                labels_json TEXT NOT NULL,
                status TEXT NOT NULL,
                health_status TEXT NOT NULL DEFAULT 'UNKNOWN',
                health_detail TEXT,
                last_health_at INTEGER,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(credential_ref) REFERENCES credential_refs(id)
            );

            CREATE TABLE IF NOT EXISTS fleet_target_snapshots (
                id TEXT PRIMARY KEY,
                selector_json TEXT NOT NULL,
                targets_json TEXT NOT NULL,
                snapshot_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS operation_plans (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                subject_type TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                state TEXT NOT NULL,
                changeset_id TEXT,
                plan_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(changeset_id) REFERENCES changesets(id)
            );

            CREATE TABLE IF NOT EXISTS operation_jobs (
                id TEXT PRIMARY KEY,
                operation_plan_id TEXT NOT NULL,
                changeset_id TEXT NOT NULL,
                executor TEXT NOT NULL,
                state TEXT NOT NULL,
                stage TEXT NOT NULL,
                plan_hash TEXT NOT NULL,
                request_json TEXT NOT NULL,
                result_json TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(operation_plan_id) REFERENCES operation_plans(id),
                FOREIGN KEY(changeset_id) REFERENCES changesets(id)
            );

            CREATE TABLE IF NOT EXISTS artifact_mirror_items (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL,
                source TEXT NOT NULL,
                destination TEXT NOT NULL,
                version TEXT NOT NULL,
                digest TEXT NOT NULL,
                labels_json TEXT NOT NULL,
                status TEXT NOT NULL,
                verification_json TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS verification_results (
                id TEXT PRIMARY KEY,
                operation_plan_id TEXT,
                changeset_id TEXT,
                subject_type TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                status TEXT NOT NULL,
                checks_json TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                observed_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(operation_plan_id) REFERENCES operation_plans(id),
                FOREIGN KEY(changeset_id) REFERENCES changesets(id)
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

        approval_cols = _columns(conn, "approvals")
        approval_additions = {
            "policy_generation": "INTEGER NOT NULL DEFAULT 1",
            "policy_id": "TEXT NOT NULL DEFAULT 'risk-baseline'",
            "policy_version": "INTEGER NOT NULL DEFAULT 1",
            "nonce": "TEXT",
            "mac": "TEXT",
            "consumed_at": "INTEGER",
        }
        for name, ddl in approval_additions.items():
            if name not in approval_cols:
                conn.execute(f"ALTER TABLE approvals ADD COLUMN {name} {ddl}")

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
                    updated_at INTEGER,
                    execution_json TEXT,
                    executed_at INTEGER
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
                "execution_json": "TEXT",
                "executed_at": "INTEGER",
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

        conn.execute(
            "INSERT OR IGNORE INTO system_state (key,value,updated_at) VALUES ('policy_generation','1',?)",
            (int(time.time()),),
        )
        blueprint_cols = _columns(conn, "cluster_blueprints")
        if "provider_version" not in blueprint_cols:
            conn.execute("ALTER TABLE cluster_blueprints ADD COLUMN provider_version TEXT NOT NULL DEFAULT 'legacy-unpinned'")
        if "addon_versions_json" not in blueprint_cols:
            conn.execute("ALTER TABLE cluster_blueprints ADD COLUMN addon_versions_json TEXT NOT NULL DEFAULT '{}'")

        conn.execute("PRAGMA user_version = 9")
        conn.commit()


def audit(conn: sqlite3.Connection, event_type: str, actor: str, subject_type: str, subject_id: str, payload: dict[str, Any] | None = None) -> None:
    conn.execute(
        "INSERT INTO audit_events (event_type,actor,subject_type,subject_id,payload_json,created_at) VALUES (?,?,?,?,?,?)",
        (event_type, actor, subject_type, subject_id, json.dumps(payload or {}, sort_keys=True), int(time.time())),
    )


def get_policy_generation(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT value FROM system_state WHERE key='policy_generation'").fetchone()
    if not row:
        now = int(time.time())
        conn.execute("INSERT INTO system_state (key,value,updated_at) VALUES ('policy_generation','1',?)", (now,))
        return 1
    return int(row["value"])


def bump_policy_generation(conn: sqlite3.Connection, actor: str, reason: str) -> tuple[int, int]:
    old = get_policy_generation(conn)
    new = old + 1
    now = int(time.time())
    conn.execute("UPDATE system_state SET value=?,updated_at=? WHERE key='policy_generation'", (str(new), now))
    conn.execute(
        "UPDATE changesets SET state='STALE_POLICY',updated_at=? WHERE policy_generation<>? AND state IN ('PLANNED','PREVIEWED','AWAITING_APPROVAL','APPROVED')",
        (now, new),
    )
    conn.execute(
        "UPDATE approvals SET status='STALE_POLICY',decided_at=?,reason=? WHERE status='APPROVED' AND changeset_id IN (SELECT id FROM changesets WHERE state='STALE_POLICY')",
        (now, f"policy generation advanced to {new}"),
    )
    audit(conn, "policy.generation_bumped", actor, "policy", "global", {"old_generation": old, "new_generation": new, "reason": reason})
    return old, new
